//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

/// A TLS provider to bootstrap TLS-enabled connections with `NIOClientTCPBootstrap`.
///
/// Example:
///
///     // TLS setup.
///     let configuration = TLSConfiguration.forClient()
///     let sslContext = try NIOSSLContext(configuration: configuration)
///
///     // Creating the "universal bootstrap" with the `NIOSSLClientTLSProvider`.
///     let tlsProvider = NIOSSLClientTLSProvider<ClientBootstrap>(context: sslContext, serverHostname: "example.com")
///     let bootstrap = NIOClientTCPBootstrap(ClientBootstrap(group: group), tls: tlsProvider)
///
///     // Bootstrapping a connection using the "universal bootstrapping mechanism"
///     let connection = bootstrap.enableTLS()
///                          .connect(to: "example.com")
///                          .wait()
public struct NIOSSLClientTLSProvider<Bootstrap: NIOClientTCPBootstrapProtocol>: NIOClientTLSProvider {
    public typealias Bootstrap = Bootstrap

    let context: NIOSSLContext
    let serverHostname: String?
    let customVerificationCallback: NIOSSLCustomVerificationCallback?

    /// Construct the TLS provider with the necessary configuration.
    public init(context: NIOSSLContext,
                serverHostname: String?,
                customVerificationCallback: NIOSSLCustomVerificationCallback? = nil) throws {
        try serverHostname.map {
            try $0.validateSNIServerName()
        }
        self.context = context
        self.serverHostname = serverHostname
        self.customVerificationCallback = customVerificationCallback
    }

    /// Enable TLS on the bootstrap. This is not a function you will typically call as a user, it is called by
    /// `NIOClientTCPBootstrap`.
    public func enableTLS(_ bootstrap: Bootstrap) -> Bootstrap {
        // NIOSSLClientHandler.init only throws because of `malloc` error and invalid SNI hostnames. We want to crash
        // on malloc error and we pre-checked the SNI hostname in `init` so that should be impossible here.
        return bootstrap.protocolHandlers {
            if let customVerificationCallback = self.customVerificationCallback {
                return [try! NIOSSLClientHandler(context: self.context,
                                                 serverHostname: self.serverHostname,
                                                 customVerificationCallback: customVerificationCallback)]
            } else {
                return [try! NIOSSLClientHandler(context: self.context,
                                                 serverHostname: self.serverHostname)]
            }
        }
    }
}
