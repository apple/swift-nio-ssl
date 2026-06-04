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
/// and ``NIOSSLQUICHandshake/advance()``.
///
/// Two outputs are deliberately *not* delegate methods. Handshake flights are
/// bounded by the call that produces them, so there is no flush callback: the
/// QUIC layer sends whatever was written once `advance()` returns. TLS alerts
/// are always fatal in QUIC, so they surface as a thrown ``NIOSSLQUICError``
/// rather than a callback.
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
}
