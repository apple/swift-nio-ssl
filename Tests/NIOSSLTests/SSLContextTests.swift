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

    private func configuredServerSSLContext(eventLoopGroup: EventLoopGroup) throws -> ServerContextWrapper {
        let wrapper = ServerContextWrapper()
        // Initialize with cert1
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(SSLContextTest.cert1)],
            privateKey: .privateKey(SSLContextTest.key1)
        )
        // Configure callback to return cert2
        config.sslContextCallback = { (values, _) in
            // Set the extension values so we can check server name later
            wrapper.sslExtensionValues = values
            // Build an alternate tls config with cert2
            let alternateConfig = TLSConfiguration.makeServerConfiguration(
                certificateChain: [.certificate(SSLContextTest.cert2)],
                privateKey: .privateKey(SSLContextTest.key2)
            )
            // Create alternate context
            let alternateContext = try NIOSSLContext(configuration: alternateConfig)
            // Create future returning the alternate context
            let future = eventLoopGroup.next().makeSucceededFuture(alternateContext)
            // Mark the wrapper expectation fulfilled so we ensure this is called
            future.whenComplete { _ in
                future.eventLoop.execute {
                    wrapper.sslContextExpectation.fulfill()
                }
            }
            return future
        }
        wrapper.context = try NIOSSLContext(configuration: config)
        return wrapper
    }

    private func assertSniResult(sniField: String?, expectedResult: String) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let clientContext = try configuredClientSSLContext()

        let serverContext = try configuredServerSSLContext(eventLoopGroup: group)

        let serverChannel = try serverTLSChannel(context: serverContext.context!, preHandlers: [], postHandlers: [], group: group)

        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(context: clientContext,
                                                 preHandlers: [],
                                                 postHandlers: [],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 serverHostname: sniField)
        defer {
            _ = try? clientChannel.close().wait()
        }

        let result = XCTWaiter.wait(for: [serverContext.sslContextExpectation], timeout: 3.0)
        if result == XCTWaiter.Result.timedOut {
            // Don't raise an exception on timeout when we expect not to
            // get a result. There are test cases where we actually
            // want to succeed if the SNI callback is never called.
            if !expectedResult.isEmpty {
                XCTFail("Timed out while awaiting expected SNI callback value.")
            }
        }

        let sniResult = serverContext.sslExtensionValues?.serverHostname

        XCTAssertEqual(sniResult, expectedResult)
    }

    func testSNIIsTransmitted() throws {
        try assertSniResult(sniField: "httpbin.org", expectedResult: "httpbin.org")
    }
}
