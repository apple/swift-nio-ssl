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

/// Whether a QUIC TLS handshake acts as the client or the server.
public enum NIOSSLQUICRole: Sendable, Hashable {
    case client
    case server
}

/// Drives a single QUIC TLS 1.3 handshake ([RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001)).
///
/// QUIC does not run TLS over the record layer; it feeds the TLS handshake
/// bytes it receives in CRYPTO frames into the handshake and consumes the
/// handshake's outputs—traffic secrets and handshake bytes to send—per
/// encryption level. A `NIOSSLQUICHandshake` wraps that state machine.
///
/// Create one from a configured ``NIOSSLContext`` (which supplies the
/// certificates, trust roots, verification policy, ALPN protocols, and SNI) and
/// supply your encoded QUIC transport parameters. Then drive it: call
/// ``advance()`` to make progress, drain what it produced—the traffic secrets
/// with ``drainSecrets()`` and the handshake bytes to send with
/// ``drainHandshakeData()``—feed peer CRYPTO bytes with
/// ``provideHandshakeData(level:_:)``, and repeat until ``advance()`` returns
/// ``State/complete``. The same calls keep working after completion:
/// application-level CRYPTO carries post-handshake messages (NewSessionTicket,
/// KeyUpdate), which ``advance()`` then processes.
///
/// To resume a later connection, offer a session captured with
/// ``drainNewSessions()`` as the ``Resumption`` at init, optionally sending
/// 0-RTT early data over it (RFC 9001 § 4.6).
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
        /// BoringSSL paused the handshake for the application to evaluate the
        /// peer's certificate chain ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)), surfaced only when
        /// `customCertificateVerification` was requested. Supply the verdict with
        /// ``resumeVerification(_:)``, then call ``advance()`` again.
        case wantsCertificateVerify([NIOSSLCertificate])
        /// BoringSSL paused the server's handshake at certificate selection so
        /// the application can choose the QUIC transport parameters to advertise
        /// after seeing the client's ([RFC 9000 § 7.4](https://datatracker.ietf.org/doc/html/rfc9000#section-7.4)),
        /// surfaced only when `selectsTransportParameters` was requested. The
        /// associated value is the peer's encoded transport parameters (the
        /// selection's input), the same bytes ``peerTransportParameters`` returns.
        /// Supply the chosen parameters with ``resumeTransportParameters(_:)``,
        /// then call ``advance()`` again.
        case wantsTransportParameters(peer: [UInt8])
        /// The server rejected the 0-RTT early data the client offered via
        /// ``Resumption/offerEarlyData(session:)``. ``advance()`` has already reset
        /// the TLS state; the caller must discard whatever it sent as 0-RTT and
        /// retransmit it after the handshake completes, then call ``advance()``
        /// again to drive the full handshake ([RFC 9001 § 4.6.1](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6.1)).
        case earlyDataRejected
    }

    /// The application's choice of transport parameters for the
    /// ``State/wantsTransportParameters(peer:)`` park, supplied to
    /// ``resumeTransportParameters(_:)``.
    public enum TransportParametersDecision: Sendable, Hashable {
        /// Advertise these encoded transport parameters
        /// ([RFC 9000 § 18](https://datatracker.ietf.org/doc/html/rfc9000#section-18)),
        /// replacing the default supplied at construction.
        case parameters([UInt8])
        /// Abandon the selection and fail the handshake: the application could
        /// not produce parameters. The next ``advance()`` throws.
        case abort
    }

    /// A traffic secret the handshake produced, drained with ``drainSecrets()``
    /// ([RFC 9001 § 5.1](https://datatracker.ietf.org/doc/html/rfc9001#section-5.1)).
    /// One value per secret BoringSSL installs: the read and write directions
    /// are reported separately, and may arrive in different ``advance()`` calls.
    ///
    /// > Warning: ``bytes`` is key material. Do not log it.
    public struct Secret: Sendable {
        /// Whether the secret decrypts received packets or protects sent ones.
        public enum Direction: Sendable, Hashable {
            case read
            case write
        }

        /// The encryption level the secret applies to.
        public var level: NIOTLSEncryptionLevel
        /// The negotiated cipher suite, as its IANA-assigned identifier
        /// (e.g. `0x1301` for `TLS_AES_128_GCM_SHA256`).
        public var cipherSuite: UInt16
        /// Whether this is the read (decryption) or write (encryption) secret.
        public var direction: Direction
        /// The traffic secret, from which packet protection keys are derived.
        public var bytes: [UInt8]
    }

    /// How this handshake resumes a prior TLS session, and whether it uses 0-RTT
    /// early data ([RFC 9001 § 4.6](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6)).
    ///
    /// The cases are role-shaped: a client offers a stored session (from a peer's
    /// earlier ``drainNewSessions()``) and may send 0-RTT over it, while a server
    /// enables acceptance of 0-RTT bound to a context. 0-RTT requires a resumed
    /// session—the early-data secret is derived from the session's resumption
    /// secret—so the session it rides is carried inside
    /// ``offerEarlyData(session:)``: there is no way to ask for early data
    /// without one.
    public enum Resumption: Sendable, Hashable {
        /// No resumption. A client performs a full handshake. A server still
        /// resumes 1-RTT transparently—it validates the client's ticket with its
        /// own key—but accepts no 0-RTT.
        case none
        /// Client: resume `session` with a 1-RTT handshake and no early data.
        /// Ignored by a server.
        case resume(session: [UInt8])
        /// Client: resume `session` and send 0-RTT early data over it. Whether the
        /// server accepted is reported by ``earlyDataAccepted`` after completion; a
        /// rejection surfaces as ``State/earlyDataRejected``. Ignored by a server.
        case offerEarlyData(session: [UInt8])
        /// Server: accept 0-RTT bound to `context`—the transport parameters plus
        /// any application state the ticket was minted under, which the offered
        /// ticket must match or 0-RTT is refused (resumption still succeeds). Must
        /// be non-empty. Ignored by a client.
        case acceptEarlyData(context: [UInt8])
    }

    private let ssl: OpaquePointer

    /// Held to keep the underlying `SSL_CTX` alive for this handshake's lifetime.
    private let context: NIOSSLContext

    /// Traffic secrets BoringSSL produced since the last ``drainSecrets()``,
    /// stashed by the `set_read_secret` / `set_write_secret` callbacks for the
    /// caller to drain after ``advance()`` ([RFC 9001 § 5.1](https://datatracker.ietf.org/doc/html/rfc9001#section-5.1)).
    private var pendingSecrets: [Secret] = []

    /// Handshake bytes BoringSSL produced since the last ``drainHandshakeData()``,
    /// stashed by the `add_handshake_data` callback for the caller to send in
    /// CRYPTO frames at their level ([RFC 9001 § 4.1.3](https://datatracker.ietf.org/doc/html/rfc9001#section-4.1.3)).
    private var pendingHandshakeData: [(level: NIOTLSEncryptionLevel, data: [UInt8])] = []

    /// Sessions BoringSSL delivered to the new-session callback since the last
    /// ``drainNewSessions()``, each serialized (`SSL_SESSION_to_bytes`) for the
    /// client to persist and later offer via ``Resumption`` ([RFC 8446 § 4.6.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1)).
    private var pendingSessions: [[UInt8]] = []

    /// The TLS alert BoringSSL last asked to send, captured from its `send_alert`
    /// callback. Surfaced as a thrown ``NIOSSLQUICError`` from the next handshake
    /// step (alerts are always fatal in QUIC).
    private var pendingAlert: UInt8?

    /// The custom certificate-verification handshake, live only when
    /// `customCertificateVerification` was requested. `idle` until BoringSSL's
    /// custom-verify callback first fires (it stashes the chain and parks at
    /// `pending`); a verdict from ``resumeVerification(_:)`` moves it to
    /// `verified` / `failed`, which the callback reports to BoringSSL on the next
    /// ``advance()``.
    private enum Verification {
        case idle
        case pending([NIOSSLCertificate])
        case verified
        case failed
    }
    private var verification: Verification = .idle

    /// The transport-parameter selection handshake, live only on a server when
    /// `selectsTransportParameters` was requested. `idle` until BoringSSL's
    /// certificate-selection callback first fires (it stashes the peer's encoded
    /// parameters and parks at `pending`); a decision from
    /// ``resumeTransportParameters(_:)`` moves it to `selected` / `failed`, which
    /// the callback acts on at the next ``advance()`` — `selected` resets the
    /// parameters to advertise and resumes, `failed` aborts the handshake. Mirrors
    /// ``Verification``, the custom-verify state machine.
    private enum TransportParameterSelection {
        case idle
        case pending([UInt8])
        case selected([UInt8])
        case failed
    }
    private var transportParameterSelection: TransportParameterSelection = .idle

    /// Creates a QUIC TLS handshake.
    ///
    /// - Parameters:
    ///   - context: a configured TLS context supplying certificates, trust,
    ///     verification, ALPN, and SNI.
    ///   - role: whether this endpoint is the client or the server.
    ///   - localTransportParameters: this endpoint's QUIC transport parameters,
    ///     already encoded ([RFC 9000 § 18](https://datatracker.ietf.org/doc/html/rfc9000#section-18)). They are carried in a TLS extension.
    ///   - serverHostname: for a client, the server name to send in the TLS SNI
    ///     extension and, under ``CertificateVerification/fullVerification``, to
    ///     require in the peer certificate (RFC 6125). Must be a DNS name, not
    ///     an IP address; `nil` sends no SNI and performs no hostname check.
    ///     Ignored for a server.
    ///   - customCertificateVerification: hand the peer's certificate chain to
    ///     the application instead of verifying it built-in ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)): the
    ///     handshake parks at ``State/wantsCertificateVerify(_:)`` and
    ///     ``resumeVerification(_:)`` supplies the verdict. For a client, the
    ///     application then owns trust evaluation *and* the hostname check,
    ///     replacing the `SSL_CTX` verification and the `serverHostname` name
    ///     check (SNI is still sent). For a server, the handshake requests the
    ///     client's certificate and verifies it the same way; whether a client
    ///     *must* present one follows the context's
    ///     ``TLSConfiguration/certificateVerification`` (`.fullVerification` /
    ///     `.noHostnameVerification` require it, `.none` leaves it optional—a
    ///     client that sends none then surfaces an empty chain for the application
    ///     to rule on). Default `false` leaves verification unchanged.
    ///   - selectsTransportParameters: for a server, pause at certificate
    ///     selection so the application can choose the transport parameters to
    ///     advertise after seeing the client's ([RFC 9000 § 7.4](https://datatracker.ietf.org/doc/html/rfc9000#section-7.4)):
    ///     the handshake parks at ``State/wantsTransportParameters(peer:)`` with
    ///     the client's encoded parameters, and ``resumeTransportParameters(_:)``
    ///     supplies the chosen value, which replaces `localTransportParameters` on
    ///     the wire. Ignored for a client, which sends its parameters in its first
    ///     flight with no peer to adapt to. Default `false` advertises
    ///     `localTransportParameters` unchanged.
    ///   - resumption: whether to resume a prior TLS session and whether to send
    ///     0-RTT early data ([RFC 9001 § 4.6](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6)); defaults to
    ///     ``Resumption/none``, a full handshake. A client captures the fresh
    ///     tickets a server issues via ``drainNewSessions()`` regardless of this
    ///     value.
    public init(
        context: NIOSSLContext,
        role: NIOSSLQUICRole,
        localTransportParameters: [UInt8],
        serverHostname: String? = nil,
        customCertificateVerification: Bool = false,
        selectsTransportParameters: Bool = false,
        resumption: Resumption = .none
    ) throws {
        guard let ssl = context.createQUICSSLHandle() else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
        self.ssl = ssl
        self.context = context

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
            // SNI is sent whenever a hostname is present: the server needs it to
            // select a certificate, independent of how the chain is verified.
            if let serverHostname {
                try Self.sendServerNameIndication(serverHostname, on: ssl)
            }
            if customCertificateVerification {
                // The application owns verification, so force VERIFY_PEER (the
                // callback must fire even when the context's mode is `.none`) and
                // skip the built-in name check—the callback owns that too. The
                // default leaves the client certificate unrequired, which is moot:
                // a server always presents one.
                Self.installCustomVerify(on: ssl)
            } else if let serverHostname,
                case .fullVerification = context.configuration.certificateVerification
            {
                try Self.requireServerHostname(serverHostname, on: ssl)
            }
        case .server:
            CNIOBoringSSL_SSL_set_accept_state(ssl)
            if customCertificateVerification {
                // Mutual TLS ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)): request the client's certificate and
                // hand its chain to the application, the same park/resume the
                // client uses for the server's. The verification mode carries
                // whether a client *must* present one; the trust decision itself
                // is the application's.
                Self.installCustomVerify(on: ssl, verification: context.configuration.certificateVerification)
            }
            if selectsTransportParameters {
                // Pause at certificate selection (RFC 9000 § 7.4): the cert_cb
                // fires after the ClientHello's extensions are parsed—so the
                // peer's transport parameters are readable—but before the
                // EncryptedExtensions flight, so resetting ours still reaches the
                // wire. Independent of custom verification, which parks later (on
                // the client's certificate) with a different SSL_get_error code.
                Self.installTransportParameterSelection(on: ssl)
            }
        }

        let transportParametersResult = localTransportParameters.withUnsafeBufferPointer {
            buffer in
            CNIOBoringSSL_SSL_set_quic_transport_params(ssl, buffer.baseAddress, buffer.count)
        }
        guard transportParametersResult == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }

        if role == .client {
            // A client captures the session tickets the server issues after the
            // handshake (RFC 8446 § 4.6.1) so the caller can persist them with
            // drainNewSessions() and resume a later connection.
            Self.enableSessionCapture(onContextOf: ssl)
        }
        try Self.apply(resumption, ssl: ssl)
    }

    deinit {
        CNIOBoringSSL_SSL_free(self.ssl)
    }

    /// Sends `serverHostname` in the TLS SNI extension so the server can select a
    /// certificate. The name must be a DNS name: SNI cannot carry an IP address,
    /// so one is rejected here.
    private static func sendServerNameIndication(_ serverHostname: String, on ssl: OpaquePointer) throws {
        try serverHostname.validateSNIServerName()
        guard serverHostname.withCString({ CNIOBoringSSL_SSL_set_tlsext_host_name(ssl, $0) }) == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
    }

    /// Requires the peer certificate to match `serverHostname` (RFC 6125), the
    /// name check BoringSSL otherwise skips; chain verification is inherited from
    /// the `SSL_CTX`. Used on the built-in path only—a custom verifier owns the
    /// name check itself.
    private static func requireServerHostname(_ serverHostname: String, on ssl: OpaquePointer) throws {
        guard serverHostname.withCString({ CNIOBoringSSL_SSL_set1_host(ssl, $0) }) == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
    }

    /// Installs the custom-verify callback that parks the handshake so the
    /// application can evaluate the peer chain ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)). `SSL_VERIFY_PEER`
    /// forces the callback to run regardless of the context's verify mode, since
    /// opting in means the application owns trust evaluation entirely. On a server
    /// it also makes the handshake request the client's certificate. Only the
    /// require-vs-optional bit is read from `verification`: `.fullVerification` /
    /// `.noHostnameVerification` add `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, so a client
    /// that sends none fails the handshake before the callback (mandatory mutual
    /// TLS); `.none` leaves it optional, reaching the callback with an empty chain.
    /// The trust decision itself is the application's, so the rest of the mode is
    /// not used.
    ///
    /// - Parameters:
    ///   - ssl: the handshake's `SSL` object.
    ///   - verification: the context's verification mode, consulted only for the
    ///     require bit. Defaults to `.none` (optional), always right for a client
    ///     (a server presents its certificate unconditionally).
    private static func installCustomVerify(
        on ssl: OpaquePointer,
        verification: CertificateVerification = .none
    ) {
        let mode =
            switch verification {
            case .fullVerification, .noHostnameVerification:
                SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            case .none:
                SSL_VERIFY_PEER
            }
        CNIOBoringSSL_SSL_set_custom_verify(ssl, mode) { ssl, _ in
            guard let handshake = NIOSSLQUICHandshake.from(ssl: ssl) else {
                return ssl_verify_invalid
            }
            return handshake.customVerify()
        }
    }

    /// Installs the certificate-selection callback that parks the server's
    /// handshake so the application can choose the transport parameters to
    /// advertise after seeing the peer's ([RFC 9000 § 7.4](https://datatracker.ietf.org/doc/html/rfc9000#section-7.4)).
    /// `cert_cb` is the one BoringSSL seam that runs after the ClientHello's
    /// extensions are parsed yet before the server's flight is produced, so the
    /// peer's parameters are readable and ours are still settable. The callback
    /// returns one to resume, zero to fail the handshake, or a negative number to
    /// pause it (`SSL_get_error` then reports `SSL_ERROR_WANT_X509_LOOKUP`).
    private static func installTransportParameterSelection(on ssl: OpaquePointer) {
        CNIOBoringSSL_SSL_set_cert_cb(
            ssl,
            { ssl, _ in
                guard let handshake = NIOSSLQUICHandshake.from(ssl: ssl) else { return 0 }
                return handshake.selectCertificate()
            },
            nil
        )
    }

    /// Enables the client session cache on the handshake's `SSL_CTX` and installs
    /// the new-session callback, so the tickets the server issues are captured for
    /// ``drainNewSessions()``. Both are `SSL_CTX`-scoped, so this affects every
    /// handshake on the same ``NIOSSLContext``. The callback is inert for a
    /// non-QUIC `SSL` (it carries no handshake in its ex_data), so a QUIC-only
    /// context is unaffected; a context shared with the record TLS path would have
    /// its own new-session callback overwritten.
    private static func enableSessionCapture(onContextOf ssl: OpaquePointer) {
        guard let context = CNIOBoringSSL_SSL_get_SSL_CTX(ssl) else { return }
        CNIOBoringSSL_SSL_CTX_set_session_cache_mode(
            context,
            SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE
        )
        CNIOBoringSSL_SSL_CTX_sess_set_new_cb(context, quicNewSessionCallback)
    }

    /// Applies the ``Resumption`` choice before the handshake begins: a client
    /// offers its session and, for 0-RTT, enables early data; a server enables
    /// early data and binds acceptance to its context. The cases are role-shaped
    /// but not role-checked—one aimed at the other role degrades to a safe no-op
    /// (a session on a server is ignored; early data with no session yields no
    /// 0-RTT).
    private static func apply(_ resumption: Resumption, ssl: OpaquePointer) throws {
        switch resumption {
        case .none:
            break
        case .resume(let session):
            try Self.setSession(session, on: ssl)
        case .offerEarlyData(let session):
            try Self.setSession(session, on: ssl)
            CNIOBoringSSL_SSL_set_early_data_enabled(ssl, 1)
        case .acceptEarlyData(let context):
            CNIOBoringSSL_SSL_set_early_data_enabled(ssl, 1)
            context.withUnsafeBufferPointer { buffer in
                _ = CNIOBoringSSL_SSL_set_quic_early_data_context(ssl, buffer.baseAddress, buffer.count)
            }
        }
    }

    /// Deserializes a stored session and offers it for resumption
    /// (`SSL_set_session`). Unparseable bytes or a refused session throw—storage
    /// corruption is a fault, not something to resume past. An expired or
    /// server-unknown ticket parses cleanly and is declined at handshake time
    /// instead, leaving ``sessionReused`` false.
    private static func setSession(_ session: [UInt8], on ssl: OpaquePointer) throws {
        let sslSession = session.withUnsafeBufferPointer { buffer in
            CNIOBoringSSL_SSL_SESSION_from_bytes(
                buffer.baseAddress,
                buffer.count,
                CNIOBoringSSL_SSL_get_SSL_CTX(ssl)
            )
        }
        guard let sslSession else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
        defer { CNIOBoringSSL_SSL_SESSION_free(sslSession) }
        guard CNIOBoringSSL_SSL_set_session(ssl, sslSession) == 1 else {
            throw NIOSSLError.handshakeFailed(.sslError(BoringSSLError.buildErrorStack()))
        }
    }

    /// Feeds handshake bytes received from the peer in a CRYPTO frame at `level`
    /// into the handshake ([RFC 9001 § 4.1.3](https://datatracker.ietf.org/doc/html/rfc9001#section-4.1.3)).
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

    /// Advances the handshake; drain the traffic secrets and handshake bytes it
    /// produces with ``drainSecrets()`` and ``drainHandshakeData()``.
    ///
    /// Before completion this drives the TLS 1.3 handshake; after completion it
    /// processes any buffered post-handshake messages, such as NewSessionTicket
    /// and KeyUpdate, provided at the application level ([RFC 9001 § 4.1.3](https://datatracker.ietf.org/doc/html/rfc9001#section-4.1.3)). The
    /// caller drives both phases the same way: feed CRYPTO bytes, call
    /// ``advance()``.
    ///
    /// - Returns: ``State/complete`` once the handshake has finished,
    ///   ``State/wantsMoreData`` if it is blocked waiting for more peer data, or
    ///   ``State/wantsCertificateVerify(_:)`` if a custom verifier must rule on
    ///   the peer chain before it can continue.
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
        if result == SSL_ERROR_EARLY_DATA_REJECTED {
            // The server refused the 0-RTT the client offered. Reset the TLS
            // state so the handshake completes in full; the caller discards its
            // 0-RTT and retransmits at 1-RTT (RFC 9001 § 4.6.1).
            CNIOBoringSSL_SSL_reset_early_data_reject(self.ssl)
            return .earlyDataRejected
        }
        let error = BoringSSLError.fromSSLGetErrorResult(result)!
        switch error {
        case .wantRead, .wantWrite:
            return .wantsMoreData
        case .wantCertificateVerify:
            // The custom-verify callback parked the handshake and stashed the
            // peer chain; surface it for the application to rule on.
            guard case .pending(let chain) = self.verification else {
                // The callback always records `.pending` before returning retry,
                // so this is unreachable; fail loudly rather than mask a bug.
                throw self.failure(error)
            }
            return .wantsCertificateVerify(chain)
        case .wantX509Lookup:
            // The certificate-selection callback parked the handshake and stashed
            // the peer's transport parameters; surface them for the application to
            // choose from. Reached only when `selectsTransportParameters` is on, so
            // `cert_cb` is the only installed pause source for this error.
            guard case .pending(let peer) = self.transportParameterSelection else {
                // The callback always records `.pending` before returning pause,
                // so this is unreachable; fail loudly rather than mask a bug.
                throw self.failure(error)
            }
            return .wantsTransportParameters(peer: peer)
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

    /// Removes and returns the traffic secrets the handshake produced since the
    /// last call, in the order BoringSSL installed them
    /// ([RFC 9001 § 5.1](https://datatracker.ietf.org/doc/html/rfc9001#section-5.1)).
    /// Drain after each ``advance()`` (and after ``provideHandshakeData(level:_:)``,
    /// which advances): a secret applies before packets at its level are
    /// processed or sent, so install it before driving the handshake further.
    ///
    /// - Returns: the secrets produced since the last drain, possibly empty.
    public func drainSecrets() -> [Secret] {
        defer { self.pendingSecrets.removeAll(keepingCapacity: true) }
        return self.pendingSecrets
    }

    /// Removes and returns the handshake bytes the handshake produced since the
    /// last call, each tagged with the encryption level it must be sent at in a
    /// CRYPTO frame ([RFC 9001 § 4.1.3](https://datatracker.ietf.org/doc/html/rfc9001#section-4.1.3)),
    /// in the order produced. Drain after each ``advance()``.
    ///
    /// - Returns: the flights produced since the last drain, possibly empty.
    public func drainHandshakeData() -> [(level: NIOTLSEncryptionLevel, data: [UInt8])] {
        defer { self.pendingHandshakeData.removeAll(keepingCapacity: true) }
        return self.pendingHandshakeData
    }

    /// Removes and returns the TLS session tickets the server issued since the
    /// last call, each serialized for the caller to persist and later offer as a
    /// ``Resumption`` ([RFC 8446 § 4.6.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1)). A TLS 1.3 server sends these
    /// after the handshake, so drain after the ``advance()`` calls that follow
    /// ``State/complete``, not only during the handshake.
    ///
    /// - Returns: the sessions captured since the last drain, possibly empty.
    public func drainNewSessions() -> [[UInt8]] {
        defer { self.pendingSessions.removeAll(keepingCapacity: true) }
        return self.pendingSessions
    }

    /// Supplies the verdict for the chain surfaced by ``State/wantsCertificateVerify(_:)``
    /// ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)). The next ``advance()`` resumes the handshake on
    /// `.certificateVerified`, or fails it with the TLS certificate alert on
    /// `.failed`. Calling this outside the `.wantsCertificateVerify` state, or
    /// more than once for it, is a programmer error.
    ///
    /// - Parameter result: the application's verdict on the peer chain.
    public func resumeVerification(_ result: NIOSSLVerificationResult) {
        guard case .pending = self.verification else {
            preconditionFailure("resumeVerification(_:) called without a pending .wantsCertificateVerify state")
        }
        switch result {
        case .certificateVerified: self.verification = .verified
        case .failed: self.verification = .failed
        }
    }

    /// Supplies the transport parameters for the park surfaced by
    /// ``State/wantsTransportParameters(peer:)`` ([RFC 9000 § 7.4](https://datatracker.ietf.org/doc/html/rfc9000#section-7.4)).
    /// On ``TransportParametersDecision/parameters(_:)`` the next ``advance()``
    /// resets the parameters to advertise and resumes the handshake; on
    /// ``TransportParametersDecision/abort`` it fails the handshake. Calling this
    /// outside the `.wantsTransportParameters` state, or more than once for it, is
    /// a programmer error.
    ///
    /// - Parameter decision: the parameters to advertise, or `.abort` to fail.
    public func resumeTransportParameters(_ decision: TransportParametersDecision) {
        guard case .pending = self.transportParameterSelection else {
            preconditionFailure(
                "resumeTransportParameters(_:) called without a pending .wantsTransportParameters state"
            )
        }
        switch decision {
        case .parameters(let encoded): self.transportParameterSelection = .selected(encoded)
        case .abort: self.transportParameterSelection = .failed
        }
    }

    /// The custom-verify callback's state machine ([RFC 9001 § 4](https://datatracker.ietf.org/doc/html/rfc9001#section-4)): on the first
    /// call it stashes the peer chain and parks (`ssl_verify_retry`); while a
    /// verdict is pending it keeps parking; once ``resumeVerification(_:)`` has
    /// recorded one it reports `ssl_verify_ok` / `ssl_verify_invalid`. This
    /// mirrors the record path's `CustomVerifyManager.process(on:)`, minus the
    /// promise.
    fileprivate func customVerify() -> ssl_verify_result_t {
        switch self.verification {
        case .idle:
            self.verification = .pending((try? SSLConnection.peerCertificateChain(fromSSL: self.ssl)) ?? [])
            return ssl_verify_retry
        case .pending:
            return ssl_verify_retry
        case .verified:
            return ssl_verify_ok
        case .failed:
            return ssl_verify_invalid
        }
    }

    /// The certificate-selection callback's state machine ([RFC 9000 § 7.4](https://datatracker.ietf.org/doc/html/rfc9000#section-7.4)):
    /// on the first call it stashes the peer's encoded transport parameters and
    /// parks (returns a negative number); while a decision is pending it keeps
    /// parking; once ``resumeTransportParameters(_:)`` has recorded one it either
    /// resets the parameters to advertise and resumes (`1`) or fails the handshake
    /// (`0`). The selection rides `cert_cb` only to read and reset the transport
    /// parameters; it never overrides BoringSSL's certificate, so the resume path
    /// returns `1` and lets the configured certificate stand. Mirrors
    /// ``customVerify()``.
    fileprivate func selectCertificate() -> CInt {
        switch self.transportParameterSelection {
        case .idle:
            self.transportParameterSelection = .pending(self.peerTransportParameters ?? [])
            return -1
        case .pending:
            return -1
        case .selected(let encoded):
            let result = encoded.withUnsafeBufferPointer { buffer in
                CNIOBoringSSL_SSL_set_quic_transport_params(self.ssl, buffer.baseAddress, buffer.count)
            }
            return result == 1 ? 1 : 0
        case .failed:
            return 0
        }
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

    /// Whether this handshake resumed a prior TLS session—an abbreviated
    /// handshake via a pre-shared key—rather than a full one. Meaningful once
    /// ``advance()`` has returned ``State/complete``.
    public var sessionReused: Bool {
        CNIOBoringSSL_SSL_session_reused(self.ssl) == 1
    }

    /// Whether the peer accepted the 0-RTT early data this handshake offered via
    /// ``Resumption/offerEarlyData(session:)`` ([RFC 9001 § 4.6.1](https://datatracker.ietf.org/doc/html/rfc9001#section-4.6.1)). Meaningful
    /// once the handshake completes; always false when no early data was offered.
    public var earlyDataAccepted: Bool {
        CNIOBoringSSL_SSL_early_data_accepted(self.ssl) == 1
    }

    /// Recovers the handshake associated with an `SSL` object inside a C
    /// callback.
    fileprivate static func from(ssl: OpaquePointer?) -> NIOSSLQUICHandshake? {
        guard let ssl, let raw = CNIOBoringSSL_SSL_get_ex_data(ssl, quicHandshakeExDataIndex) else {
            return nil
        }
        return Unmanaged<NIOSSLQUICHandshake>.fromOpaque(raw).takeUnretainedValue()
    }

    // MARK: Output capture (called from the C trampolines)

    fileprivate func handleSecret(
        level: ssl_encryption_level_t,
        cipher: OpaquePointer?,
        secret: UnsafePointer<UInt8>?,
        secretLength: Int,
        isRead: Bool
    ) -> Bool {
        // BoringSSL always supplies the negotiated cipher alongside a secret; a
        // null cipher is a broken contract, so fail the callback loudly.
        guard let secret, let cipher else { return false }
        // Copy the key material out of the callback immediately; the caller
        // drains it after `advance()` returns.
        let bytes = Array(UnsafeBufferPointer(start: secret, count: secretLength))
        let cipherSuite = CNIOBoringSSL_SSL_CIPHER_get_protocol_id(cipher)
        self.pendingSecrets.append(
            Secret(
                level: NIOTLSEncryptionLevel(level),
                cipherSuite: cipherSuite,
                direction: isRead ? .read : .write,
                bytes: bytes
            )
        )
        return true
    }

    fileprivate func handleHandshakeData(
        level: ssl_encryption_level_t,
        data: UnsafePointer<UInt8>?,
        length: Int
    ) -> Bool {
        guard let data else { return false }
        let bytes = Array(UnsafeBufferPointer(start: data, count: length))
        self.pendingHandshakeData.append((NIOTLSEncryptionLevel(level), bytes))
        return true
    }

    /// Serializes a session BoringSSL delivered to the new-session callback and
    /// stashes it for ``drainNewSessions()``. Called from the C trampoline, which
    /// has already null-checked the session.
    fileprivate func captureSession(_ session: OpaquePointer) {
        var out: UnsafeMutablePointer<UInt8>? = nil
        var outLength = 0
        guard CNIOBoringSSL_SSL_SESSION_to_bytes(session, &out, &outLength) == 1, let out else {
            return
        }
        defer { CNIOBoringSSL_OPENSSL_free(out) }
        self.pendingSessions.append(Array(UnsafeBufferPointer(start: out, count: outLength)))
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

/// The new-session callback installed on a client `SSL_CTX` by
/// ``NIOSSLQUICHandshake``. BoringSSL invokes it with each session the server
/// issues; it recovers the handshake from the `SSL`'s ex_data and stashes the
/// serialized session for ``NIOSSLQUICHandshake/drainNewSessions()``. It returns
/// zero: the bytes are copied out, so BoringSSL keeps ownership of the session
/// and frees it. Inert for a non-QUIC `SSL`, which carries no handshake.
private let quicNewSessionCallback: @convention(c) (OpaquePointer?, OpaquePointer?) -> Int32 = { ssl, session in
    guard let session, let handshake = NIOSSLQUICHandshake.from(ssl: ssl) else { return 0 }
    handshake.captureSession(session)
    return 0
}
