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
}
