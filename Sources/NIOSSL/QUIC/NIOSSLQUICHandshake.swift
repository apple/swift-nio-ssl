//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
import NIOCore

/// Drives a single QUIC TLS 1.3 handshake (RFC 9001).
///
/// QUIC does not run TLS over the record layer; it feeds the TLS handshake
/// bytes it receives in CRYPTO frames into the handshake and consumes the
/// handshake's outputs — traffic secrets and handshake bytes to send — per
/// encryption level. A `NIOSSLQUICHandshake` wraps that state machine.
///
/// Create one from a configured ``NIOSSLContext`` (which supplies the
/// certificates, trust roots, verification policy, ALPN protocols, and SNI),
/// supply your encoded QUIC transport parameters, and provide a
/// ``NIOSSLQUICDelegate`` to receive the handshake's outputs. Then drive it:
/// call ``advance()`` to make progress, feed peer CRYPTO bytes with
/// ``provideHandshakeData(level:_:)``, and repeat until ``advance()`` returns
/// ``State/complete``. The same two calls keep working after completion:
/// application-level CRYPTO carries post-handshake messages (NewSessionTicket,
/// KeyUpdate), which ``advance()`` then processes.
///
/// > Note: This type is not thread-safe. Use it from a single, consistent
/// > execution context (typically a connection's event loop).
public final class NIOSSLQUICHandshake {
    /// The state of the handshake after a call to ``advance()``.
    public enum State: Sendable, Hashable {
        /// The handshake needs more data from the peer to make progress.
        case wantsMoreData
        /// The handshake has completed successfully.
        case complete
    }

    private let ssl: OpaquePointer

    /// Held to keep the underlying `SSL_CTX` alive for this handshake's lifetime.
    private let context: NIOSSLContext

    /// The delegate is held weakly: the QUIC connection that owns this handshake
    /// is typically also its delegate, so a strong reference would cycle.
    private weak var delegate: (any NIOSSLQUICDelegate)?

    /// The TLS alert BoringSSL last asked to send, captured from its `send_alert`
    /// callback. Surfaced as a thrown ``NIOSSLQUICError`` from the next handshake
    /// step (alerts are always fatal in QUIC).
    private var pendingAlert: UInt8?

    /// Creates a QUIC TLS handshake.
    ///
    /// - Parameters:
    ///   - context: a configured TLS context supplying certificates, trust,
    ///     verification, ALPN, and SNI.
    ///   - role: whether this endpoint is the client or the server.
    ///   - serverHostname: for a client, the server name to send in the TLS SNI
    ///     extension and, under ``CertificateVerification/fullVerification``, to
    ///     require in the peer certificate (RFC 6125). Must be a DNS name, not
    ///     an IP address; `nil` sends no SNI and performs no hostname check.
    ///     Ignored for a server.
    ///   - localTransportParameters: this endpoint's QUIC transport parameters,
    ///     already encoded (RFC 9000 § 18). They are carried in a TLS extension.
    ///   - delegate: receives the handshake's outputs.
    public init(
        context: NIOSSLContext,
        role: NIOSSLQUICRole,
        serverHostname: String? = nil,
        localTransportParameters: [UInt8],
        delegate: any NIOSSLQUICDelegate
    ) throws {
        guard let ssl = context.createQUICSSLHandle() else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
        self.ssl = ssl
        self.context = context
        self.delegate = delegate

        // Recover `self` inside the C callbacks via ex_data, mirroring
        // SSLConnection. The reference is unowned: the SSL object never outlives
        // this handshake (it is freed in deinit).
        let pointerToSelf = Unmanaged.passUnretained(self).toOpaque()
        CNIOBoringSSL_SSL_set_ex_data(ssl, quicHandshakeExDataIndex, pointerToSelf)

        guard CNIOBoringSSL_SSL_set_quic_method(ssl, quicMethodPointer) == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }

        switch role {
        case .client:
            CNIOBoringSSL_SSL_set_connect_state(ssl)
            if let serverHostname {
                try Self.useServerHostname(
                    serverHostname,
                    on: ssl,
                    verification: context.configuration.certificateVerification
                )
            }
        case .server:
            CNIOBoringSSL_SSL_set_accept_state(ssl)
        }

        let transportParametersResult = localTransportParameters.withUnsafeBufferPointer {
            buffer in
            CNIOBoringSSL_SSL_set_quic_transport_params(ssl, buffer.baseAddress, buffer.count)
        }
        guard transportParametersResult == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
    }

    deinit {
        CNIOBoringSSL_SSL_free(self.ssl)
    }

    /// Sends `serverHostname` in the TLS SNI extension and, under
    /// ``CertificateVerification/fullVerification``, requires it to match the
    /// peer certificate. Chain verification is inherited from the `SSL_CTX`;
    /// `SSL_set1_host` adds the name check BoringSSL otherwise skips (RFC 6125).
    /// The name must be a DNS name: SNI cannot carry an IP address, so one is
    /// rejected before either call.
    private static func useServerHostname(
        _ serverHostname: String,
        on ssl: OpaquePointer,
        verification: CertificateVerification
    ) throws {
        try serverHostname.validateSNIServerName()
        guard serverHostname.withCString({ CNIOBoringSSL_SSL_set_tlsext_host_name(ssl, $0) }) == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
        if case .fullVerification = verification {
            guard serverHostname.withCString({ CNIOBoringSSL_SSL_set1_host(ssl, $0) }) == 1 else {
                throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
            }
        }
    }

    /// Feeds handshake bytes received from the peer in a CRYPTO frame at `level`
    /// into the handshake (RFC 9001 § 4.1.3).
    public func provideHandshakeData(level: NIOTLSEncryptionLevel, _ data: ByteBuffer) throws {
        guard data.readableBytes > 0 else { return }
        let result = data.withUnsafeReadableBytes { raw -> Int32 in
            CNIOBoringSSL_SSL_provide_quic_data(
                self.ssl,
                level.boringSSLLevel,
                raw.baseAddress?.assumingMemoryBound(to: UInt8.self),
                raw.count
            )
        }
        guard result == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
    }

    /// Advances the handshake, invoking the delegate as secrets become
    /// available and handshake bytes are produced.
    ///
    /// Before completion this drives the TLS 1.3 handshake; after completion it
    /// processes any buffered post-handshake messages, such as NewSessionTicket
    /// and KeyUpdate, provided at the application level (RFC 9001 § 4.1.3). The
    /// caller drives both phases the same way: feed CRYPTO bytes, call
    /// ``advance()``.
    ///
    /// - Returns: ``State/complete`` once the handshake has finished, or
    ///   ``State/wantsMoreData`` if it is blocked waiting for more peer data.
    /// - Throws: ``NIOSSLQUICError`` carrying the TLS alert if the handshake
    ///   raised one, otherwise ``NIOSSLError/handshakeFailed(_:)``.
    @discardableResult
    public func advance() throws -> State {
        // Once the handshake is out of its initial state, progress means
        // draining buffered post-handshake messages: BoringSSL routes those
        // through SSL_process_quic_post_handshake, not SSL_do_handshake.
        guard CNIOBoringSSL_SSL_in_init(self.ssl) == 1 else {
            let rc = CNIOBoringSSL_SSL_process_quic_post_handshake(self.ssl)
            guard rc == 1 else {
                let result = CNIOBoringSSL_SSL_get_error(self.ssl, rc)
                let error = BoringSSLError.fromSSLGetErrorResult(result)!
                throw self.failure(error)
            }
            return .complete
        }
        let rc = CNIOBoringSSL_SSL_do_handshake(self.ssl)
        if rc == 1 {
            return .complete
        }
        let result = CNIOBoringSSL_SSL_get_error(self.ssl, rc)
        let error = BoringSSLError.fromSSLGetErrorResult(result)!
        switch error {
        case .wantRead, .wantWrite:
            return .wantsMoreData
        default:
            throw self.failure(error)
        }
    }

    /// The error to throw from a failed handshake step: the TLS alert the
    /// handshake raised, if any (alerts are always fatal in QUIC), otherwise the
    /// underlying BoringSSL error.
    private func failure(_ error: BoringSSLError) -> any Error {
        // Consume the alert: a fatal alert ends the handshake, but post-handshake
        // processing can fail later for unrelated reasons, and a stale alert must
        // not masquerade as that failure's cause.
        if let alert = self.pendingAlert {
            self.pendingAlert = nil
            return NIOSSLQUICError.tlsAlert(alert)
        }
        return NIOSSLError.handshakeFailed(error)
    }

    /// The peer's encoded QUIC transport parameters, available once the peer's
    /// TLS extension has been received, or `nil` otherwise.
    public var peerTransportParameters: [UInt8]? {
        var pointer: UnsafePointer<UInt8>? = nil
        var length = 0
        CNIOBoringSSL_SSL_get_peer_quic_transport_params(self.ssl, &pointer, &length)
        guard let pointer, length > 0 else { return nil }
        return Array(UnsafeBufferPointer(start: pointer, count: length))
    }

    /// The application protocol negotiated via ALPN, or `nil` if none was
    /// negotiated.
    ///
    /// Named to match `TLSUserEvent.handshakeCompleted(negotiatedProtocol:)`,
    /// which carries the same ALPN result for the record-based TLS path.
    public var negotiatedProtocol: String? {
        var pointer: UnsafePointer<UInt8>? = nil
        var length: UInt32 = 0
        CNIOBoringSSL_SSL_get0_alpn_selected(self.ssl, &pointer, &length)
        guard let pointer, length > 0 else { return nil }
        return String(decoding: UnsafeBufferPointer(start: pointer, count: Int(length)), as: UTF8.self)
    }

    /// Recovers the handshake associated with an `SSL` object inside a C
    /// callback.
    fileprivate static func from(ssl: OpaquePointer?) -> NIOSSLQUICHandshake? {
        guard let ssl, let raw = CNIOBoringSSL_SSL_get_ex_data(ssl, quicHandshakeExDataIndex) else {
            return nil
        }
        return Unmanaged<NIOSSLQUICHandshake>.fromOpaque(raw).takeUnretainedValue()
    }

    // MARK: Delegate dispatch (called from the C trampolines)

    fileprivate func handleSecret(
        level: ssl_encryption_level_t,
        cipher: OpaquePointer?,
        secret: UnsafePointer<UInt8>?,
        secretLength: Int,
        isRead: Bool
    ) -> Bool {
        // BoringSSL always supplies the negotiated cipher alongside a secret; a
        // null cipher is a broken contract, so fail the callback loudly.
        guard let delegate = self.delegate, let secret, let cipher else { return false }
        let bytes = Array(UnsafeBufferPointer(start: secret, count: secretLength))
        let cipherSuite = CNIOBoringSSL_SSL_CIPHER_get_protocol_id(cipher)
        let mapped = NIOTLSEncryptionLevel(level)
        if isRead {
            delegate.setReadSecret(level: mapped, cipherSuite: cipherSuite, secret: bytes)
        } else {
            delegate.setWriteSecret(level: mapped, cipherSuite: cipherSuite, secret: bytes)
        }
        return true
    }

    fileprivate func handleHandshakeData(
        level: ssl_encryption_level_t,
        data: UnsafePointer<UInt8>?,
        length: Int
    ) -> Bool {
        guard let delegate = self.delegate, let data else { return false }
        let bytes = Array(UnsafeBufferPointer(start: data, count: length))
        delegate.writeHandshakeData(level: NIOTLSEncryptionLevel(level), bytes)
        return true
    }

    /// Records the TLS alert BoringSSL wishes to send. In QUIC, alerts are
    /// always fatal; the alert is surfaced as a thrown ``NIOSSLQUICError`` from
    /// the next handshake step rather than as a delegate callback.
    fileprivate func recordAlert(_ alert: UInt8) {
        self.pendingAlert = alert
    }
}

// A QUIC handshake owns mutable BoringSSL state and is not safe to use
// concurrently: it is intended to be driven from a single connection's
// execution context. Declared explicitly non-Sendable to satisfy
// -require-explicit-sendable.
@available(*, unavailable)
extension NIOSSLQUICHandshake: Sendable {}

// MARK: - SSL_QUIC_METHOD bridging

/// The ex_data slot used to associate a ``NIOSSLQUICHandshake`` with its `SSL`.
private let quicHandshakeExDataIndex = CNIOBoringSSL_SSL_get_ex_new_index(0, nil, nil, nil, nil)

/// A process-lifetime `SSL_QUIC_METHOD` whose callbacks trampoline into the
/// handshake's delegate. Allocated once; the pointer must remain valid for as
/// long as any `SSL` references it, so it is never freed.
///
/// `nonisolated(unsafe)`: the pointee is written once during initialization and
/// only ever read thereafter (BoringSSL treats it as `const`), so concurrent
/// reads are safe without further synchronization.
private nonisolated(unsafe) let quicMethodPointer: UnsafePointer<SSL_QUIC_METHOD> = {
    let pointer = UnsafeMutablePointer<SSL_QUIC_METHOD>.allocate(capacity: 1)
    pointer.initialize(
        to: SSL_QUIC_METHOD(
            set_read_secret: { ssl, level, cipher, secret, secretLength in
                let ok = NIOSSLQUICHandshake.from(ssl: ssl)?.handleSecret(
                    level: level,
                    cipher: cipher,
                    secret: secret,
                    secretLength: secretLength,
                    isRead: true
                )
                return (ok ?? false) ? 1 : 0
            },
            set_write_secret: { ssl, level, cipher, secret, secretLength in
                let ok = NIOSSLQUICHandshake.from(ssl: ssl)?.handleSecret(
                    level: level,
                    cipher: cipher,
                    secret: secret,
                    secretLength: secretLength,
                    isRead: false
                )
                return (ok ?? false) ? 1 : 0
            },
            add_handshake_data: { ssl, level, data, length in
                let ok = NIOSSLQUICHandshake.from(ssl: ssl)?.handleHandshakeData(
                    level: level,
                    data: data,
                    length: length
                )
                return (ok ?? false) ? 1 : 0
            },
            flush_flight: { _ in
                // A flight is bounded by the call that produced it; the QUIC
                // layer flushes after `advance()` returns. No-op.
                1
            },
            send_alert: { ssl, _, alert in
                NIOSSLQUICHandshake.from(ssl: ssl)?.recordAlert(alert)
                return 1
            }
        )
    )
    return UnsafePointer(pointer)
}()
