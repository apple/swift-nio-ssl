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

/// A TLS encryption level, as used by QUIC (RFC 9001 § 2.1).
///
/// QUIC drives the TLS 1.3 handshake directly and protects packets with keys
/// derived from the traffic secrets produced at each level. The handshake
/// progresses through these levels in order, except that ``earlyData`` (0-RTT)
/// is only used when early data is offered and accepted.
public enum NIOTLSEncryptionLevel: Sendable, Hashable {
    /// The Initial encryption level, protected with keys derived from the
    /// Destination Connection ID (RFC 9001 § 5.2).
    case initial

    /// The 0-RTT (early data) encryption level.
    case earlyData

    /// The Handshake encryption level.
    case handshake

    /// The 1-RTT (application data) encryption level.
    case application
}

extension NIOTLSEncryptionLevel {
    /// Bridges from BoringSSL's `ssl_encryption_level_t`.
    internal init(_ level: ssl_encryption_level_t) {
        if level == ssl_encryption_initial {
            self = .initial
        } else if level == ssl_encryption_early_data {
            self = .earlyData
        } else if level == ssl_encryption_handshake {
            self = .handshake
        } else {
            self = .application
        }
    }

    /// Bridges to BoringSSL's `ssl_encryption_level_t`.
    internal var boringSSLLevel: ssl_encryption_level_t {
        switch self {
        case .initial:
            return ssl_encryption_initial
        case .earlyData:
            return ssl_encryption_early_data
        case .handshake:
            return ssl_encryption_handshake
        case .application:
            return ssl_encryption_application
        }
    }
}
