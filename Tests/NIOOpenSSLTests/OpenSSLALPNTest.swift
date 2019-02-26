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
import CNIOBoringSSL
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

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
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
        originalBuffer.writeString("Hello")
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

    func testBasicALPNNegotiation() throws {
        let context: NIOOpenSSL.SSLContext
        context = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"]))

        XCTAssertNoThrow(try assertNegotiatedProtocol(protocol: "h2", serverContext: context, clientContext: context))
    }

    func testBasicALPNNegotiationPrefersServerPriority() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        serverCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"]))
        clientCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["http/1.1", "h2"]))

        XCTAssertNoThrow(try assertNegotiatedProtocol(protocol: "h2", serverContext: serverCtx, clientContext: clientCtx))
    }

    func testBasicALPNNegotiationNoOverlap() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        serverCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"]))
        clientCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["spdy/3", "webrtc"]))
        XCTAssertNoThrow(try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx))
    }

    func testBasicALPNNegotiationNotOfferedByClient() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        serverCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"]))
        clientCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: []))
        XCTAssertNoThrow(try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx))
    }

    func testBasicALPNNegotiationNotSupportedByServer() throws {
        let serverCtx: NIOOpenSSL.SSLContext
        let clientCtx: NIOOpenSSL.SSLContext
        serverCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: []))
        clientCtx = try assertNoThrowWithValue(configuredSSLContextWithAlpnProtocols(protocols: ["h2", "http/1.1"]))

        XCTAssertNoThrow(try assertNegotiatedProtocol(protocol: nil, serverContext: serverCtx, clientContext: clientCtx))
    }
}
