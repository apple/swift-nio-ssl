//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
import Darwin.C
#elseif os(Linux) || os(FreeBSD) || os(Android)
import Glibc
#else
#error("unsupported os")
#endif

extension String {
    private func isIPAddress() -> Bool {
        // We need some scratch space to let inet_pton write into.
        var ipv4Addr = in_addr()
        var ipv6Addr = in6_addr()

        return self.withCString { ptr in
            return inet_pton(AF_INET, ptr, &ipv4Addr) == 1 ||
                   inet_pton(AF_INET6, ptr, &ipv6Addr) == 1
        }
    }

    func validateSNIServerName() throws {
        guard !self.isIPAddress() else {
            throw NIOSSLExtraError.cannotUseIPAddressInSNI(ipAddress: self)
        }

        // no 0 bytes
        guard !self.utf8.contains(0) else {
            throw NIOSSLExtraError.invalidSNIHostname
        }

        guard (1 ... 255).contains(self.utf8.count) else {
            throw NIOSSLExtraError.invalidSNIHostname
        }
    }
}

/// A channel handler that wraps a channel in TLS using NIOSSL.
/// This handler can be used in channels that are acting as the client
/// in the TLS dialog. For server connections, use the ``NIOSSLServerHandler``.
public final class NIOSSLClientHandler: NIOSSLHandler {
    /// Construct a new ``NIOSSLClientHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - serverHostname: The hostname of the server we're trying to connect to, if known. This will be used in the SNI extension,
    ///         and used to validate the server certificate.
    public convenience init(context: NIOSSLContext, serverHostname: String?) throws {
        try self.init(context: context, serverHostname: serverHostname, optionalCustomVerificationCallback: nil, optionalAdditionalPeerCertificateVerificationCallback: nil)
    }

    @available(*, deprecated, renamed: "init(context:serverHostname:customVerificationCallback:)")
    public init(context: NIOSSLContext, serverHostname: String?, verificationCallback: NIOSSLVerificationCallback? = nil) throws {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setConnectState()
        if let serverHostname = serverHostname {
            try serverHostname.validateSNIServerName()

            // IP addresses must not be provided in the SNI extension, so filter them.
            do {
                try connection.setServerName(name: serverHostname)
            } catch {
                preconditionFailure("Bug in NIOSSL (please report): \(Array(serverHostname.utf8)) passed NIOSSL's hostname test but failed in BoringSSL.")
            }
        }

        if let verificationCallback = verificationCallback {
            connection.setVerificationCallback(verificationCallback)
        }

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout, additionalPeerCertificateVerificationCallback: nil, maxWriteSize: NIOSSLHandler.defaultMaxWriteSize)
    }

    /// Construct a new ``NIOSSLClientHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - serverHostname: The hostname of the server we're trying to connect to, if known. This will be used in the SNI extension,
    ///         and used to validate the server certificate.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    public convenience init(context: NIOSSLContext, serverHostname: String?, customVerificationCallback: @escaping NIOSSLCustomVerificationCallback) throws {
        try self.init(context: context, serverHostname: serverHostname, optionalCustomVerificationCallback: customVerificationCallback, optionalAdditionalPeerCertificateVerificationCallback: nil)
    }
    
    /// - warning: This API is not guaranteed to be stable and is likely to be changed without further notice, hence the underscore prefix.
    public static func _makeSSLClientHandler(
        context: NIOSSLContext,
        serverHostname: String?,
        additionalPeerCertificateVerificationCallback: @escaping _NIOAdditionalPeerCertificateVerificationCallback
    ) throws -> Self {
        try .init(context: context, serverHostname: serverHostname, optionalCustomVerificationCallback: nil, optionalAdditionalPeerCertificateVerificationCallback: additionalPeerCertificateVerificationCallback)
    }

    // This exists to handle the explosion of initializers we got when I tried to deprecate the first one. At least they all pass through one path now.
    internal init(
        context: NIOSSLContext,
        serverHostname: String?,
        optionalCustomVerificationCallback: NIOSSLCustomVerificationCallback?,
        optionalAdditionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?,
        maxWriteSize: Int = defaultMaxWriteSize
    ) throws {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setConnectState()
        if let serverHostname = serverHostname {
            try serverHostname.validateSNIServerName()

            // IP addresses must not be provided in the SNI extension, so filter them.
            do {
                try connection.setServerName(name: serverHostname)
            } catch {
                preconditionFailure("Bug in NIOSSL (please report): \(Array(serverHostname.utf8)) passed NIOSSL's hostname test but failed in BoringSSL.")
            }
        }

        if let verificationCallback = optionalCustomVerificationCallback {
            connection.setCustomVerificationCallback(CustomVerifyManager(callback: verificationCallback))
        }

        super.init(
            connection: connection,
            shutdownTimeout: context.configuration.shutdownTimeout,
            additionalPeerCertificateVerificationCallback: optionalAdditionalPeerCertificateVerificationCallback,
            maxWriteSize: maxWriteSize
        )
    }
}

@available(*, unavailable)
extension NIOSSLClientHandler: Sendable {}
