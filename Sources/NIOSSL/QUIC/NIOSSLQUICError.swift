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

/// An error raised by a ``NIOSSLQUICHandshake``.
public enum NIOSSLQUICError: Error, Hashable, Sendable {
    /// The handshake raised a fatal TLS alert. The associated value is the TLS
    /// alert description (RFC 8446 § 6). In QUIC, alerts are always fatal; the
    /// QUIC layer maps this to a CONNECTION_CLOSE frame with error code
    /// `0x0100 | alert` (RFC 9001 § 4.8).
    case tlsAlert(UInt8)

    /// The handshake failed because the peer broke a rule QUIC layers on TLS,
    /// rather than TLS itself: CRYPTO data at a previously installed encryption
    /// level extending past previously received data, or left unconsumed when
    /// keys for a higher level arrived (RFC 9001 § 4.1.3); a post-handshake TLS
    /// message QUIC forbids, such as CertificateRequest (§ 4.4); a
    /// NewSessionTicket whose early_data extension is not 0xffffffff (§ 4.6.1);
    /// or a ClientHello using TLS compatibility mode (§ 8.4). RFC 9001 requires
    /// the QUIC layer to close such connections with PROTOCOL_VIOLATION (0x0a)
    /// rather than the `0x0100 | alert` mapping above.
    case protocolViolation
}
