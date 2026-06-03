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

/// Whether a QUIC TLS handshake acts as the client or the server.
public enum NIOSSLQUICRole: Sendable, Hashable {
    case client
    case server
}

/// Receives the outputs of a ``NIOSSLQUICHandshake`` as the TLS 1.3 handshake
/// progresses.
///
/// A QUIC implementation provides one of these to drive packet protection and
/// to carry handshake bytes in CRYPTO frames (RFC 9001). All methods are invoked
/// synchronously from within ``NIOSSLQUICHandshake/provideHandshakeData(level:_:)``
/// and ``NIOSSLQUICHandshake/advance()``; none of the byte buffers handed to the
/// delegate remain valid after the call returns, so a delegate that needs to
/// retain them must copy.
///
/// > Warning: The `secret` values are key material. Do not log them.
public protocol NIOSSLQUICDelegate: AnyObject {
    /// Installs the read (decryption) traffic secret for `level`.
    ///
    /// - Parameters:
    ///   - level: the encryption level the secret applies to.
    ///   - cipherSuite: the negotiated cipher suite, as its IANA-assigned
    ///     identifier (e.g. `0x1301` for `TLS_AES_128_GCM_SHA256`).
    ///   - secret: the traffic secret, from which packet protection keys are
    ///     derived (RFC 9001 § 5.1).
    func setReadSecret(level: NIOTLSEncryptionLevel, cipherSuite: UInt16, secret: [UInt8])

    /// Installs the write (encryption) traffic secret for `level`.
    func setWriteSecret(level: NIOTLSEncryptionLevel, cipherSuite: UInt16, secret: [UInt8])

    /// Provides handshake bytes that must be sent to the peer in CRYPTO frames
    /// at `level`.
    func writeHandshakeData(level: NIOTLSEncryptionLevel, _ data: [UInt8])

    /// Signals a flight boundary: handshake data provided since the last flush
    /// may now be sent.
    func flushFlight()

    /// Signals that the handshake produced a fatal TLS alert, which the QUIC
    /// layer should surface as a CONNECTION_CLOSE frame (RFC 9001 § 4.8).
    func sendAlert(level: NIOTLSEncryptionLevel, alert: UInt8)
}
