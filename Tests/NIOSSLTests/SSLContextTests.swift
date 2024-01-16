//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import NIO
import NIOTLS
import NIOEmbedded
@testable import NIOSSL

class SSLContextTest: XCTestCase {
    fileprivate class ServerContextWrapper {
        let sslContextExpectation: XCTestExpectation
        var context: NIOSSLContext?
        var sslExtensionValues: NIOSSLClientExtensionValues?

        init() {
            self.sslContextExpectation = XCTestExpectation(description: "SSL Context callback called")
        }
    }

    static var cert1: NIOSSLCertificate!
    static var key1: NIOSSLPrivateKey!

    static var cert2: NIOSSLCertificate!
    static var key2: NIOSSLPrivateKey!

    override class func setUp() {
        super.setUp()
        let (cert1, key1) = generateSelfSignedCert()
        SSLContextTest.cert1 = cert1
        SSLContextTest.key1 = key1
        let (cert2, key2) = generateSelfSignedCert()
        SSLContextTest.cert2 = cert2
        SSLContextTest.key2 = key2
    }

    private func configuredClientSSLContext() throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(SSLContextTest.cert2)],
            privateKey: .privateKey(SSLContextTest.key2)
        )
        config.trustRoots = .certificates([SSLContextTest.cert2])
        let context = try NIOSSLContext(configuration: config)
        return context
    }

    private func configuredServerSSLContext(eventLoop: EventLoop) throws -> NIOSSLContext {
        // Initialize with cert1
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(SSLContextTest.cert1)],
            privateKey: .privateKey(SSLContextTest.key1)
        )
        // Configure callback to return cert2
        config.sslContextCallback = { (values, _) in
            let alternateConfig = TLSConfiguration.makeServerConfiguration(
                certificateChain: [.certificate(SSLContextTest.cert2)],
                privateKey: .privateKey(SSLContextTest.key2)
            )
            let alternateContext = try NIOSSLContext(configuration: alternateConfig)
            return eventLoop.makeSucceededFuture(alternateContext)
        }
        return try NIOSSLContext(configuration: config)
    }

    private func assertSniResult(sniField: String?, expectedResult: String) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)

        let clientContext = try configuredClientSSLContext()
        let serverContext = try configuredServerSSLContext(eventLoop: group.next())

        let serverChannel = try serverTLSChannel(context: serverContext, preHandlers: [], postHandlers: [], group: group)
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(context: clientContext,
                                                 preHandlers: [],
                                                 postHandlers: [handshakeWatcher],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 serverHostname: sniField)
        defer {
            _ = try? clientChannel.close().wait()
        }

        try handshakeResultPromise.futureResult.wait()
        XCTAssertEqual(true, true)
    }

    func testSNIIsTransmitted() throws {
        try assertSniResult(sniField: "httpbin.org", expectedResult: "httpbin.org")
    }
}
