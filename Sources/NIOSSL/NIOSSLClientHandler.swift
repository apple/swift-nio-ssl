//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

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
/// in the TLS dialog. For server connections, use the `NIOSSLServerHandler`.
public final class NIOSSLClientHandler: NIOSSLHandler {
    public convenience init(context: NIOSSLContext, serverHostname: String?) throws {
        try self.init(context: context, serverHostname: serverHostname, optionalCustomVerificationCallback: nil)
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

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout)
    }


    public convenience init(context: NIOSSLContext, serverHostname: String?, customVerificationCallback: @escaping NIOSSLCustomVerificationCallback) throws {
        try self.init(context: context, serverHostname: serverHostname, optionalCustomVerificationCallback: customVerificationCallback)
    }

    // This exists to handle the explosion of initializers we got when I tried to deprecate the first one. At least they all pass through one path now.
    private init(context: NIOSSLContext, serverHostname: String?, optionalCustomVerificationCallback: NIOSSLCustomVerificationCallback?) throws {
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

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout)
    }
}
