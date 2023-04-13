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

/// A channel handler that wraps a channel in TLS using NIOSSL. This
/// handler can be used in channels that are acting as the server in
/// the TLS dialog. For client connections, use the ``NIOSSLClientHandler``.
public final class NIOSSLServerHandler: NIOSSLHandler {
    /// Construct a new ``NIOSSLServerHandler`` with the given `context`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    public convenience init(context: NIOSSLContext) {
        self.init(context: context, optionalCustomVerificationCallback: nil, optionalAdditionalPeerCertificateVerificationCallback: nil)
    }

    @available(*, deprecated, renamed: "init(context:customVerificationCallback:)")
    public init(context: NIOSSLContext, verificationCallback: NIOSSLVerificationCallback? = nil) throws {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setAcceptState()

        if let verificationCallback = verificationCallback {
            connection.setVerificationCallback(verificationCallback)
        }

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout, additionalPeerCertificateVerificationCallback: nil, maxWriteSize: NIOSSLHandler.defaultMaxWriteSize)
    }

    /// Construct a new ``NIOSSLClientHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    public convenience init(context: NIOSSLContext, customVerificationCallback: @escaping NIOSSLCustomVerificationCallback) {
        self.init(context: context, optionalCustomVerificationCallback: customVerificationCallback, optionalAdditionalPeerCertificateVerificationCallback: nil)
    }
    
    /// - warning: This API is not guaranteed to be stable and is likely to be changed without further notice, hence the underscore prefix.
    public static func _makeSSLServerHandler(
        context: NIOSSLContext,
        additionalPeerCertificateVerificationCallback: @escaping _NIOAdditionalPeerCertificateVerificationCallback
    ) -> Self {
        .init(context: context, optionalCustomVerificationCallback: nil, optionalAdditionalPeerCertificateVerificationCallback: additionalPeerCertificateVerificationCallback)
    }

    /// This exists to handle the explosion of initializers I got when I deprecated the first one.
    private init(
        context: NIOSSLContext,
        optionalCustomVerificationCallback: NIOSSLCustomVerificationCallback?,
        optionalAdditionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?
    ) {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setAcceptState()

        if let customVerificationCallback = optionalCustomVerificationCallback {
            connection.setCustomVerificationCallback(.init(callback: customVerificationCallback))
        }

        super.init(
            connection: connection,
            shutdownTimeout: context.configuration.shutdownTimeout,
            additionalPeerCertificateVerificationCallback: optionalAdditionalPeerCertificateVerificationCallback,
            maxWriteSize: NIOSSLHandler.defaultMaxWriteSize
        )
    }
}

@available(*, unavailable)
extension NIOSSLServerHandler: Sendable {}
