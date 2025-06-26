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
import NIOEmbedded
import NIOPosix
import NIOTLS
import XCTest

@testable import NIOSSL

final class SSLContextTest: XCTestCase {
    fileprivate class ServerContextWrapper {
        let sslContextExpectation: XCTestExpectation
        var context: NIOSSLContext?
        var sslExtensionValues: NIOSSLClientExtensionValues?

        init() {
            self.sslContextExpectation = XCTestExpectation(description: "SSL Context callback called")
        }
    }

    fileprivate enum TestError: Error {
        case contextError
    }

    static let _certAndKey1 = generateSelfSignedCert()
    static let cert1 = SSLContextTest._certAndKey1.0
    static let key1 = SSLContextTest._certAndKey1.1

    static let _certAndKey2 = generateSelfSignedCert()
    static let cert2 = SSLContextTest._certAndKey2.0
    static let key2 = SSLContextTest._certAndKey2.1

    private func configuredClientSSLContext() throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(SSLContextTest.cert2)],
            privateKey: .privateKey(SSLContextTest.key2)
        )
        config.trustRoots = .certificates([SSLContextTest.cert2])
        let context = try NIOSSLContext(configuration: config)
        return context
    }

    private func configuredServerSSLContext(
        eventLoop: EventLoop,
        throwing error: TestError? = nil
    ) throws -> NIOSSLContext {
        // Initialize with cert1
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(SSLContextTest.cert1)],
            privateKey: .privateKey(SSLContextTest.key1)
        )
        // Configure callback to return cert2
        config.sslContextCallback = { (values, promise) in
            promise.completeWithTask {
                if let error {
                    throw error
                }
                var override = NIOSSLContextConfigurationOverride()
                override.certificateChain = [.certificate(SSLContextTest.cert2)]
                override.privateKey = .privateKey(SSLContextTest.key2)
                return override
            }
        }
        return try NIOSSLContext(configuration: config)
    }

    private func assertSniResult(sniField: String?, expectedResult: String?) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)

        let clientContext = try configuredClientSSLContext()
        let serverContext = try configuredServerSSLContext(eventLoop: group.next())

        let sniPromise: EventLoopPromise<SNIResult> = group.next().makePromise()

        let serverChannel = try serverTLSChannel(
            context: serverContext,
            preHandlers: [
                ByteToMessageHandler(
                    SNIHandler {
                        sniPromise.succeed($0)
                        return group.next().makeSucceededFuture(())
                    }
                )
            ],
            postHandlers: [],
            group: group
        )
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [handshakeWatcher],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: sniField
        )
        defer {
            _ = try? clientChannel.close().wait()
        }

        // This promise ensures we completed the handshake.
        // If the ssl context callback doesn't properly resume
        // the handshake this will never resolve.
        XCTAssertNoThrow(try handshakeResultPromise.futureResult.wait())

        let sniResult = try sniPromise.futureResult.wait()
        if let expectedResult {
            XCTAssertEqual(sniResult, .hostname(expectedResult))
        } else {
            XCTAssertEqual(sniResult, .fallback)
        }
    }

    private func assertSniError(sniField: String?, expectedError: TestError) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)

        let clientContext = try configuredClientSSLContext()
        let serverContext = try configuredServerSSLContext(eventLoop: group.next(), throwing: expectedError)

        let sniPromise: EventLoopPromise<SNIResult> = group.next().makePromise()

        let eventHandler = ErrorCatcher<any Error>()

        let serverChannel = try serverTLSChannel(
            context: serverContext,
            preHandlers: [
                ByteToMessageHandler(
                    SNIHandler {
                        sniPromise.succeed($0)
                        return group.next().makeSucceededFuture(())
                    }
                )
            ],
            postHandlers: [eventHandler],
            group: group
        )
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [handshakeWatcher],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: sniField
        )
        defer {
            _ = try? clientChannel.close().wait()
        }

        // This promise ensures we completed the handshake.
        // If the ssl context callback doesn't properly resume
        // the handshake this will never resolve.
        XCTAssertThrowsError(try handshakeResultPromise.futureResult.wait())

        // The first caught item should be the error from the context callback.
        try serverChannel.eventLoop.submit {
            XCTAssertEqual(eventHandler.errors.count, 2)
            switch eventHandler.errors[0] {
            case let error as TestError:
                XCTAssertEqual(error, expectedError)
            default:
                XCTFail("Unexpected error: \(eventHandler.errors[0])")
            }
        }.wait()
    }

    func testSNIIsTransmitted() throws {
        try assertSniResult(sniField: "httpbin.org", expectedResult: "httpbin.org")
    }

    func testSNIIsNotTransmitted() throws {
        try assertSniResult(sniField: nil, expectedResult: nil)
    }

    func testSNIContextError() throws {
        try assertSniError(sniField: "httpbin.org", expectedError: .contextError)
    }
}
