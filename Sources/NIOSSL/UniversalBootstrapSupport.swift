//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A TLS provider to bootstrap TLS-enabled connections with `NIOClientTCPBootstrap`.
///
/// Example:
///
///     // TLS setup.
///     let configuration = TLSConfiguration.makeClientConfiguration()
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
    #if swift(>=5.7)
    /// See ``NIOSSLCustomVerificationCallback`` for more documentation
    let customVerificationCallback: (@Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) -> Void)?
    /// See ``_NIOAdditionalPeerCertificateVerificationCallback`` for more documentation
    let additionalPeerCertificateVerificationCallback: (@Sendable (NIOSSLCertificate, Channel) -> EventLoopFuture<Void>)?
    #else
    let customVerificationCallback: NIOSSLCustomVerificationCallback?
    let additionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?
    #endif

    #if swift(>=5.7)
    internal init(
        context: NIOSSLContext,
        serverHostname: String?,
        customVerificationCallback: (@Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) -> Void)? = nil,
        additionalPeerCertificateVerificationCallback: (@Sendable (NIOSSLCertificate, Channel) -> EventLoopFuture<Void>)? = nil
    ) throws {
        try serverHostname.map {
            try $0.validateSNIServerName()
        }
        self.context = context
        self.serverHostname = serverHostname
        self.customVerificationCallback = customVerificationCallback
        self.additionalPeerCertificateVerificationCallback = additionalPeerCertificateVerificationCallback
    }
    #else
    internal init(
        context: NIOSSLContext,
        serverHostname: String?,
        customVerificationCallback: NIOSSLCustomVerificationCallback? = nil,
        additionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback? = nil
    ) throws {
        try serverHostname.map {
            try $0.validateSNIServerName()
        }
        self.context = context
        self.serverHostname = serverHostname
        self.customVerificationCallback = customVerificationCallback
        self.additionalPeerCertificateVerificationCallback = additionalPeerCertificateVerificationCallback
    }
    #endif
    
    #if swift(>=5.7)
    /// Construct the TLS provider with the necessary configuration.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use with the connection.
    ///     - serverHostname: The hostname of the server we're trying to connect to, if known. This will be used in the SNI extension,
    ///         and used to validate the server certificate.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic. See ``NIOSSLCustomVerificationCallback`` for complete documentation.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    @preconcurrency
    public init(
        context: NIOSSLContext,
        serverHostname: String?,
        customVerificationCallback: (@Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) -> Void)? = nil
    ) throws {
        try self.init(context: context, serverHostname: serverHostname, customVerificationCallback: customVerificationCallback, additionalPeerCertificateVerificationCallback: nil)
    }
    #else
    /// Construct the TLS provider with the necessary configuration.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use with the connection.
    ///     - serverHostname: The hostname of the server we're trying to connect to, if known. This will be used in the SNI extension,
    ///         and used to validate the server certificate.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    public init(
        context: NIOSSLContext,
        serverHostname: String?,
        customVerificationCallback: NIOSSLCustomVerificationCallback? = nil
    ) throws {
        try self.init(context: context, serverHostname: serverHostname, customVerificationCallback: customVerificationCallback, additionalPeerCertificateVerificationCallback: nil)
    }
    #endif

    /// Enable TLS on the bootstrap. This is not a function you will typically call as a user, it is called by
    /// `NIOClientTCPBootstrap`.
    public func enableTLS(_ bootstrap: Bootstrap) -> Bootstrap {
        // NIOSSLClientHandler.init only throws because of `malloc` error and invalid SNI hostnames. We want to crash
        // on malloc error and we pre-checked the SNI hostname in `init` so that should be impossible here.
        return bootstrap.protocolHandlers {
            [
                try! NIOSSLClientHandler(
                    context: self.context,
                    serverHostname: self.serverHostname,
                    optionalCustomVerificationCallback: customVerificationCallback,
                    optionalAdditionalPeerCertificateVerificationCallback: additionalPeerCertificateVerificationCallback
                )
            ]
        }
    }
}
