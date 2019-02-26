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
@testable import NIOOpenSSL
import NIOTLS

class ErrorCatcher<T: Error>: ChannelInboundHandler {
    public typealias InboundIn = Any
    public var errors: [T]

    public init() {
        errors = []
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        errors.append(error as! T)
    }
}

class HandshakeCompletedHandler: ChannelInboundHandler {
    public typealias InboundIn = Any
    public var handshakeSucceeded = false

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            self.handshakeSucceeded = true
        }
        context.fireUserInboundEventTriggered(event)
    }
}

class TLSConfigurationTest: XCTestCase {
    static var cert1: OpenSSLCertificate!
    static var key1: OpenSSLPrivateKey!

    static var cert2: OpenSSLCertificate!
    static var key2: OpenSSLPrivateKey!

    override class func setUp() {
        super.setUp()
        var (cert, key) = generateSelfSignedCert()
        TLSConfigurationTest.cert1 = cert
        TLSConfigurationTest.key1 = key

        (cert, key) = generateSelfSignedCert()
        TLSConfigurationTest.cert2 = cert
        TLSConfigurationTest.key2 = key
    }

    func assertHandshakeError(withClientConfig clientConfig: TLSConfiguration,
                              andServerConfig serverConfig: TLSConfiguration,
                              errorTextContains message: String,
                              file: StaticString = #file,
                              line: UInt = #line) throws {
        return try assertHandshakeError(withClientConfig: clientConfig,
                                        andServerConfig: serverConfig,
                                        errorTextContainsAnyOf: [message],
                                        file: file,
                                        line: line)
    }

    func assertHandshakeError(withClientConfig clientConfig: TLSConfiguration,
                              andServerConfig serverConfig: TLSConfiguration,
                              errorTextContainsAnyOf messages: [String],
                              file: StaticString = #file,
                              line: UInt = #line) throws {
        let clientContext = try assertNoThrowWithValue(SSLContext(configuration: clientConfig), file: file, line: line)
        let serverContext = try assertNoThrowWithValue(SSLContext(configuration: serverConfig), file: file, line: line)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<NIOOpenSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(serverTLSChannel(context: serverContext, handlers: [], group: group), file: file, line: line)
        let clientChannel = try assertNoThrowWithValue(clientTLSChannel(context: clientContext, preHandlers:[], postHandlers: [eventHandler, handshakeHandler], group: group, connectingTo: serverChannel.localAddress!), file: file, line: line)

        // We expect the channel to be closed fairly swiftly as the handshake should fail.
        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 1)

            switch eventHandler.errors[0] {
            case .handshakeFailed(.sslError(let errs)):
                let correctError: Bool = messages.map { errs[0].description.contains($0) }.reduce(false) { $0 || $1 }
                XCTAssert(correctError, errs[0].description, file: file, line: line)
            default:
                XCTFail("Unexpected error: \(eventHandler.errors[0])", file: file, line: line)
            }

            XCTAssertFalse(handshakeHandler.handshakeSucceeded, file: file, line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    func assertPostHandshakeError(withClientConfig clientConfig: TLSConfiguration,
                                  andServerConfig serverConfig: TLSConfiguration,
                                  errorTextContains message: String,
                                  file: StaticString = #file,
                                  line: UInt = #line) throws {
        let clientContext = try assertNoThrowWithValue(SSLContext(configuration: clientConfig), file: file, line: line)
        let serverContext = try assertNoThrowWithValue(SSLContext(configuration: serverConfig), file: file, line: line)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<OpenSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(serverTLSChannel(context: serverContext, handlers: [], group: group), file: file, line: line)
        let clientChannel = try assertNoThrowWithValue(clientTLSChannel(context: clientContext, preHandlers:[], postHandlers: [eventHandler, handshakeHandler], group: group, connectingTo: serverChannel.localAddress!), file: file, line: line)

        // We expect the channel to be closed fairly swiftly as the handshake should fail.
        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 1, file: file, line: line)

            switch eventHandler.errors[0] {
            case .sslError(let errs):
                XCTAssertEqual(errs.count, 1, file: file, line: line)
                let correctError = errs[0].description.contains(message)
                XCTAssert(correctError, errs[0].description, file: file, line: line)
            default:
                XCTFail("Unexpected error: \(eventHandler.errors[0])", file: file, line: line)
            }

            XCTAssertTrue(handshakeHandler.handshakeSucceeded, file: file, line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    func testNonOverlappingTLSVersions() throws {
        var clientConfig = TLSConfiguration.clientDefault
        clientConfig.minimumTLSVersion = .tlsv11
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      maximumTLSVersion: .tlsv1)

        try assertHandshakeError(withClientConfig: clientConfig,
                                 andServerConfig: serverConfig,
                                 errorTextContains: "ALERT_PROTOCOL_VERSION")
    }

    func testNonOverlappingCipherSuitesPreTLS13() throws {
        let clientConfig = TLSConfiguration.forClient(cipherSuites: "AES128",
                                                      maximumTLSVersion: .tlsv12,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert1]))
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      cipherSuites: "AES256",
                                                      maximumTLSVersion: .tlsv12)

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContains: "ALERT_HANDSHAKE_FAILURE")
    }

    func testCannotVerifySelfSigned() throws {
        let clientConfig = TLSConfiguration.forClient()
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1))

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContains: "CERTIFICATE_VERIFY_FAILED")
    }

    func testServerCannotValidateClientPreTLS13() throws {
        let clientConfig = TLSConfiguration.forClient(maximumTLSVersion: .tlsv12,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert1]),
                                                      certificateChain: [.certificate(TLSConfigurationTest.cert2)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key2))
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      maximumTLSVersion: .tlsv12,
                                                      certificateVerification: .noHostnameVerification)

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContains: "ALERT_UNKNOWN_CA")
    }

    func testServerCannotValidateClientPostTLS13() throws {
        let clientConfig = TLSConfiguration.forClient(minimumTLSVersion: .tlsv13,
                                                      certificateVerification: .noHostnameVerification,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert1]),
                                                      certificateChain: [.certificate(TLSConfigurationTest.cert2)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key2))
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      minimumTLSVersion: .tlsv13,
                                                      certificateVerification: .noHostnameVerification)

        try assertPostHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContains: "ALERT_UNKNOWN_CA")
    }

    func testMutualValidation() throws {
        let clientConfig = TLSConfiguration.forClient(trustRoots: .certificates([TLSConfigurationTest.cert1]),
                                                      certificateChain: [.certificate(TLSConfigurationTest.cert2)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key2))
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      certificateVerification: .noHostnameVerification,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert2]))

        let clientContext = try SSLContext(configuration: clientConfig)
        let serverContext = try SSLContext(configuration: serverConfig)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = EventRecorderHandler<TLSUserEvent>()
        let serverChannel = try serverTLSChannel(context: serverContext, handlers: [], group: group)
        let clientChannel = try clientTLSChannel(context: clientContext, preHandlers: [], postHandlers: [eventHandler], group: group, connectingTo: serverChannel.localAddress!, serverHostname: "localhost")

        // Wait for a successful flush: that indicates the channel is up.
        var buf = clientChannel.allocator.buffer(capacity: 5)
        buf.writeString("hello")

        // Check that we got a handshakeComplete message indicating mutual validation.
        let flushFuture = clientChannel.writeAndFlush(buf)
        flushFuture.whenComplete { _ in
            let handshakeEvents = eventHandler.events.filter {
                switch $0 {
                case .UserEvent(.handshakeCompleted):
                    return true
                default:
                    return false
                }
            }

            XCTAssertEqual(handshakeEvents.count, 1)
        }
        try flushFuture.wait()
    }

    func testNonexistentFileObject() throws {
        let clientConfig = TLSConfiguration.forClient(trustRoots: .file("/thispathbetternotexist/bogus.foo"))

        do {
            _ = try SSLContext(configuration: clientConfig)
            XCTFail("Did not throw")
        } catch NIOOpenSSLError.noSuchFilesystemObject {
            // This is fine
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
