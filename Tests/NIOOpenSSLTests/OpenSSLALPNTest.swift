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

import XCTest
import CNIOOpenSSL
import NIO
import NIOTLS
import NIOOpenSSL


class OpenSSLALPNTest: XCTestCase {
    static var cert: OpenSSLCertificate!
    static var key: OpenSSLPrivateKey!

    override class func setUp() {
        super.setUp()
        let (cert, key) = generateSelfSignedCert()
        OpenSSLIntegrationTest.cert = cert
        OpenSSLIntegrationTest.key = key
    }

    private func configuredSSLContextWithAlpnProtocols(protocols: [String]) throws -> NIOOpenSSL.SSLContext {
        let config = TLSConfiguration.forServer(certificateChain: [.certificate(OpenSSLIntegrationTest.cert)],
                                                privateKey: .privateKey(OpenSSLIntegrationTest.key),
                                                trustRoots: .certificates([OpenSSLIntegrationTest.cert]),
                                                applicationProtocols: protocols)
        return try SSLContext(configuration: config)
    }

    private func assertNegotiatedProtocol(protocol: String?,
                                          serverContext: NIOOpenSSL.SSLContext,
                                          clientContext: NIOOpenSSL.SSLContext) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let serverHandler = EventRecorderHandler<TLSUserEvent>()

        let serverChannel = try serverTLSChannel(context: serverContext,
                                                 handlers: [serverHandler, PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(context: clientContext,
                                                 preHandlers: [],
                                                 postHandlers: [],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()
        _ = try completionPromise.futureResult.wait()

        let expectedEvents: [EventRecorderHandler<TLSUserEvent>.RecordedEvents] = [
            .Registered,
            .Active,
            .UserEvent(TLSUserEvent.handshakeCompleted(negotiatedProtocol: `protocol`)),
            .Read,
            .ReadComplete
        ]
        XCTAssertEqual(expectedEvents, serverHandler.events)
    }

    private func assertDoesNotNegotiate(serverContext: NIOOpenSSL.SSLContext, clientContext: NIOOpenSSL.SSLContext) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let clientHandler = EventRecorderHandler<TLSUserEvent>()
        let errorHandler = ErrorCatcher<NIOOpenSSLError>()
        let serverChannel = try serverTLSChannel(context: serverContext,
                                                 handlers: [errorHandler],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(context: clientContext,
                                                 preHandlers: [],
                                                 postHandlers: [clientHandler],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)

        try clientChannel.closeFuture.wait()

        let expectedEvents: [EventRecorderHandler<TLSUserEvent>.RecordedEvents] = [
            .Registered,
            .Active,
            .Inactive,
            .Unregistered
        ]
        XCTAssertEqual(expectedEvents, clientHandler.events)

        XCTAssertEqual(errorHandler.errors.count, 1)
        switch errorHandler.errors.first {
        case .some(.handshakeFailed(.sslError)):
            // Expected
            break
        default:
            XCTFail("Unexpected error: \(String(describing: errorHandler.errors.first))")
        }
    }

    func testBasicALPNNegotiation() throws {
        let ctx: NIOOpenSSL.SSLContext
        do {
            ctx = try configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"])
        } catch OpenSSLError.failedToSetALPN {
            XCTAssertTrue(CNIOOpenSSL_OpenSSL_version_num() < 0x010002000)
            return
        }

        try assertNegotiatedProtocol(protocol: "h2", serverContext: ctx, clientContext: ctx)
    }

    func testBasicALPNNegotiationPrefersServerPriority() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        do {
            serverCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"])
            clientCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["http/1.1", "h2"])
        } catch OpenSSLError.failedToSetALPN {
            XCTAssertTrue(CNIOOpenSSL_OpenSSL_version_num() < 0x010002000)
            return
        }

        try assertNegotiatedProtocol(protocol: "h2", serverContext: serverCtx, clientContext: clientCtx)
    }

    func testBasicALPNNegotiationNoOverlap() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        do {
            serverCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"])
            clientCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["spdy/3", "webrtc"])
        } catch OpenSSLError.failedToSetALPN {
            XCTAssertTrue(CNIOOpenSSL_OpenSSL_version_num() < 0x010002000)
            return
        }

        if (CNIOOpenSSL_OpenSSL_version_num() < 0x010100000) || (CNIOOpenSSL_is_libressl() == 1) {
            try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx)
        } else {
            try assertDoesNotNegotiate(serverContext: serverCtx, clientContext: clientCtx)
        }
    }

    func testBasicALPNNegotiationNotOfferedByClient() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        do {
            serverCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"])
            clientCtx = try configuredSSLContextWithAlpnProtocols(protocols: [])
        } catch OpenSSLError.failedToSetALPN {
            XCTAssertTrue(CNIOOpenSSL_OpenSSL_version_num() < 0x010002000)
            return
        }

        try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx)
    }

    func testBasicALPNNegotiationNotSupportedByServer() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        do {
            serverCtx = try configuredSSLContextWithAlpnProtocols(protocols: [])
            clientCtx = try configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"])
        } catch OpenSSLError.failedToSetALPN {
            XCTAssertTrue(CNIOOpenSSL_OpenSSL_version_num() < 0x010002000)
            return
        }

        try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx)
    }
}
