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
        self.init(
            context: context,
            optionalCustomVerificationCallbackManager: nil,
            optionalAdditionalPeerCertificateVerificationCallback: nil
        )
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

        super.init(
            connection: connection,
            shutdownTimeout: context.configuration.shutdownTimeout,
            additionalPeerCertificateVerificationCallback: nil,
            maxWriteSize: NIOSSLHandler.defaultMaxWriteSize,
            configuration: .init()
        )
    }

    /// Construct a new ``NIOSSLServerHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    ///
    /// - Note: Use ``init(context:customVerificationCallbackWithMetadata:)`` to provide a custom verification
    ///   callback where the peer's *validated* certificate chain can be returned. This data can then be accessed from
    ///   the handler.
    public convenience init(
        context: NIOSSLContext,
        customVerificationCallback: @escaping NIOSSLCustomVerificationCallback
    ) {
        self.init(
            context: context,
            optionalCustomVerificationCallbackManager: CustomVerifyManager(callback: customVerificationCallback),
            optionalAdditionalPeerCertificateVerificationCallback: nil
        )
    }

    /// Construct a new ``NIOSSLServerHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - customVerificationCallbackWithMetadata: A callback to use that will override NIOSSL's normal verification
    ///         logic. If validation is successful, the peer's validated certificate chain can be returned, and later
    ///         accessed via ``NIOSSLHandler/peerValidatedCertificateChain``. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has
    ///         ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    ///
    ///       - This callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed
    ///       them. Therefore, a validated chain must be derived *within* this callback (potentially involving fetching
    ///       additional intermediate certificates). The *validated* certificate chain returned in the promise result
    ///       **must** be a verified path to a trusted root. Importantly, the certificates presented by the peer should
    ///       not be assumed to be valid.
    public convenience init(
        context: NIOSSLContext,
        customVerificationCallbackWithMetadata: @escaping NIOSSLCustomVerificationCallbackWithMetadata
    ) {
        self.init(
            context: context,
            optionalCustomVerificationCallbackManager: CustomVerifyManager(
                callback: customVerificationCallbackWithMetadata
            ),
            optionalAdditionalPeerCertificateVerificationCallback: nil
        )
    }

    /// Construct a new ``NIOSSLServerHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - customVerificationCallback: A callback to use that will override NIOSSL's normal verification logic.
    ///
    ///         If set, this callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed them. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    ///     - configuration: Configuration for this handler.
    ///
    /// - Note: Use ``init(context:configuration:customVerificationCallbackWithMetadata:)`` to provide a custom
    ///   verification callback where the peer's *validated* certificate chain can be returned. This data can then be
    ///   accessed from the handler.
    public convenience init(
        context: NIOSSLContext,
        customVerificationCallback: NIOSSLCustomVerificationCallback? = nil,
        configuration: Configuration
    ) {
        self.init(
            context: context,
            optionalCustomVerificationCallbackManager: customVerificationCallback.map(CustomVerifyManager.init),
            optionalAdditionalPeerCertificateVerificationCallback: nil,
            configuration: configuration
        )
    }

    /// Construct a new ``NIOSSLServerHandler`` with the given `context` and a specific `serverHostname`.
    ///
    /// - parameters:
    ///     - context: The ``NIOSSLContext`` to use on this connection.
    ///     - configuration: Configuration for this handler.
    ///     - customVerificationCallbackWithMetadata: A callback to use that will override NIOSSL's normal verification
    ///         logic. If validation is successful, the peer's validated certificate chain can be returned, and later
    ///         accessed via ``NIOSSLHandler/peerValidatedCertificateChain``. The callback will not be used if the
    ///         ``TLSConfiguration`` that was used to construct the ``NIOSSLContext`` has
    ///         ``TLSConfiguration/certificateVerification`` set to ``CertificateVerification/none``.
    ///
    ///       - This callback is provided the certificates presented by the peer. NIOSSL will not have pre-processed
    ///       them. Therefore, a validated chain must be derived *within* this callback (potentially involving fetching
    ///       additional intermediate certificates). The *validated* certificate chain returned in the promise result
    ///       **must** be a verified path to a trusted root. Importantly, the certificates presented by the peer should
    ///       not be assumed to be valid.
    public convenience init(
        context: NIOSSLContext,
        configuration: Configuration,
        customVerificationCallbackWithMetadata: @escaping NIOSSLCustomVerificationCallbackWithMetadata
    ) {
        self.init(
            context: context,
            optionalCustomVerificationCallbackManager: CustomVerifyManager(
                callback: customVerificationCallbackWithMetadata
            ),
            optionalAdditionalPeerCertificateVerificationCallback: nil,
            configuration: configuration
        )
    }

    /// - warning: This API is not guaranteed to be stable and is likely to be changed without further notice, hence the underscore prefix.
    public static func _makeSSLServerHandler(
        context: NIOSSLContext,
        additionalPeerCertificateVerificationCallback: @escaping _NIOAdditionalPeerCertificateVerificationCallback
    ) -> Self {
        .init(
            context: context,
            optionalCustomVerificationCallbackManager: nil,
            optionalAdditionalPeerCertificateVerificationCallback: additionalPeerCertificateVerificationCallback
        )
    }

    /// This exists to handle the explosion of initializers I got when I deprecated the first one.
    private init(
        context: NIOSSLContext,
        optionalCustomVerificationCallbackManager: CustomVerifyManager?,
        optionalAdditionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?,
        configuration: Configuration = .init()
    ) {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setAcceptState()

        if let customVerificationCallbackManager = optionalCustomVerificationCallbackManager {
            connection.setCustomVerificationCallback(customVerificationCallbackManager)
        }

        super.init(
            connection: connection,
            shutdownTimeout: context.configuration.shutdownTimeout,
            additionalPeerCertificateVerificationCallback: optionalAdditionalPeerCertificateVerificationCallback,
            maxWriteSize: NIOSSLHandler.defaultMaxWriteSize,
            configuration: configuration
        )
    }
}

// This conformance is technically redundant - Swift 6.2 compiler finally caught this
#if compiler(<6.2)
@available(*, unavailable)
extension NIOSSLServerHandler: Sendable {}
#endif
