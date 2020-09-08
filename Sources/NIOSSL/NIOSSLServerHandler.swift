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

/// A channel handler that wraps a channel in TLS using NIOSSL. This
/// handler can be used in channels that are acting as the server in
/// the TLS dialog. For client connections, use the `NIOSSLClientHandler`.
public final class NIOSSLServerHandler: NIOSSLHandler {
    public convenience init(context: NIOSSLContext) {
        self.init(context: context, optionalCustomVerificationCallback: nil)
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

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout)
    }

    public convenience init(context: NIOSSLContext, customVerificationCallback: @escaping NIOSSLCustomVerificationCallback) {
        self.init(context: context, optionalCustomVerificationCallback: customVerificationCallback)
    }

    /// This exists to handle the explosion of initializers I got when I deprecated the first one.
    private init(context: NIOSSLContext, optionalCustomVerificationCallback: NIOSSLCustomVerificationCallback?) {
        guard let connection = context.createConnection() else {
            fatalError("Failed to create new connection in NIOSSLContext")
        }

        connection.setAcceptState()

        if let customVerificationCallback = optionalCustomVerificationCallback {
            connection.setCustomVerificationCallback(.init(callback: customVerificationCallback))
        }

        super.init(connection: connection, shutdownTimeout: context.configuration.shutdownTimeout)
    }
}
