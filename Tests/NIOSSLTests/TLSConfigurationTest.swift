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
#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import NIO
@testable import NIOSSL
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

class WaitForHandshakeHandler: ChannelInboundHandler {
    public typealias InboundIn = Any
    public var handshakeResult: EventLoopFuture<Void> {
        return self.handshakeResultPromise.futureResult
    }

    private var handshakeResultPromise: EventLoopPromise<Void>

    init(handshakeResultPromise: EventLoopPromise<Void>) {
        self.handshakeResultPromise = handshakeResultPromise
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            self.handshakeResultPromise.succeed(())
        }
        context.fireUserInboundEventTriggered(event)
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        if let error = error as? NIOSSLError, case .handshakeFailed = error {
            self.handshakeResultPromise.fail(error)
        }
        context.fireErrorCaught(error)
    }
}

class TLSConfigurationTest: XCTestCase {
    static var cert1: NIOSSLCertificate!
    static var key1: NIOSSLPrivateKey!

    static var cert2: NIOSSLCertificate!
    static var key2: NIOSSLPrivateKey!

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
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig), file: file, line: line)
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig), file: file, line: line)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<NIOSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(serverTLSChannel(context: serverContext, handlers: [], group: group), file: file, line: line)
        let clientChannel = try assertNoThrowWithValue(clientTLSChannel(context: clientContext, preHandlers:[], postHandlers: [eventHandler, handshakeHandler], group: group, connectingTo: serverChannel.localAddress!), file: file, line: line)

        // We expect the channel to be closed fairly swiftly as the handshake should fail.
        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 1)

            switch eventHandler.errors[0] {
            case .handshakeFailed(.sslError(let errs)):
                let correctError: Bool = messages.map { errs[0].description.contains($0) }.reduce(false) { $0 || $1 }
                XCTAssert(correctError, errs[0].description, file: (file), line: line)
            default:
                XCTFail("Unexpected error: \(eventHandler.errors[0])", file: (file), line: line)
            }

            XCTAssertFalse(handshakeHandler.handshakeSucceeded, file: (file), line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    func assertPostHandshakeError(withClientConfig clientConfig: TLSConfiguration,
                                  andServerConfig serverConfig: TLSConfiguration,
                                  errorTextContainsAnyOf messages: [String],
                                  file: StaticString = #file,
                                  line: UInt = #line) throws {
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig), file: file, line: line)
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig), file: file, line: line)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<BoringSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(serverTLSChannel(context: serverContext, handlers: [], group: group), file: file, line: line)
        let clientChannel = try assertNoThrowWithValue(clientTLSChannel(context: clientContext, preHandlers:[], postHandlers: [eventHandler, handshakeHandler], group: group, connectingTo: serverChannel.localAddress!), file: file, line: line)

        // We expect the channel to be closed fairly swiftly as the handshake should fail.
        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 1, file: (file), line: line)

            switch eventHandler.errors[0] {
            case .sslError(let errs):
                XCTAssertEqual(errs.count, 1, file: (file), line: line)
                let correctError: Bool = messages.map { errs[0].description.contains($0) }.reduce(false) { $0 || $1 }
                XCTAssert(correctError, errs[0].description, file: (file), line: line)
            default:
                XCTFail("Unexpected error: \(eventHandler.errors[0])", file: (file), line: line)
            }

            XCTAssertTrue(handshakeHandler.handshakeSucceeded, file: (file), line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    /// Performs a connection in memory and validates that the handshake was successful.
    ///
    /// - NOTE: This function should only be used when you know that there is no custom verification
    /// callback in use, otherwise it will not be thread-safe.
    func assertHandshakeSucceededInMemory(withClientConfig clientConfig: TLSConfiguration,
                                          andServerConfig serverConfig: TLSConfiguration,
                                          file: StaticString = #file,
                                          line: UInt = #line) throws {
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))

        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server case to throw
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        XCTAssertNoThrow(try serverChannel.pipeline.addHandler(NIOSSLServerHandler(context: serverContext)).wait(), file: (file), line: line)
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(NIOSSLClientHandler(context: clientContext, serverHostname: nil)).wait(), file: (file), line: line)
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait(), file: (file), line: line)

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel), file: (file), line: line)
        XCTAssertTrue(handshakeHandler.handshakeSucceeded, file: (file), line: line)

        _ = serverChannel.close()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
    }

    /// Performs a connection using a real event loop and validates that the handshake was successful.
    ///
    /// This function is thread-safe in the presence of custom verification callbacks.
    func assertHandshakeSucceededEventLoop(withClientConfig clientConfig: TLSConfiguration,
                                           andServerConfig serverConfig: TLSConfiguration,
                                           file: StaticString = #file,
                                           line: UInt = #line) throws {
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig), file: file, line: line)
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig), file: file, line: line)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<BoringSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)

        let serverChannel = try assertNoThrowWithValue(serverTLSChannel(context: serverContext, handlers: [], group: group), file: file, line: line)
        let clientChannel = try assertNoThrowWithValue(clientTLSChannel(context: clientContext, preHandlers:[], postHandlers: [eventHandler, handshakeWatcher, handshakeHandler], group: group, connectingTo: serverChannel.localAddress!), file: file, line: line)

        handshakeWatcher.handshakeResult.whenComplete { c in
            _ = clientChannel.close()
        }

        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 0, file: file, line: line)
            XCTAssertTrue(handshakeHandler.handshakeSucceeded, file: file, line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    func assertHandshakeSucceeded(withClientConfig clientConfig: TLSConfiguration,
                                  andServerConfig serverConfig: TLSConfiguration,
                                  file: StaticString = #file,
                                  line: UInt = #line) throws {
        // The only use of a custom callback is on Darwin...
        #if os(Linux)
        return try assertHandshakeSucceededInMemory(withClientConfig: clientConfig, andServerConfig: serverConfig, file: file, line: line)

        #else
        return try assertHandshakeSucceededEventLoop(withClientConfig: clientConfig, andServerConfig: serverConfig, file: file, line: line)
        #endif
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

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContainsAnyOf: ["ALERT_UNKNOWN_CA", "ALERT_CERTIFICATE_UNKNOWN"])
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

        try assertPostHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContainsAnyOf: ["ALERT_UNKNOWN_CA", "ALERT_CERTIFICATE_UNKNOWN"])
    }

    func testMutualValidationRequiresClientCertificatePreTLS13() throws {
        let clientConfig = TLSConfiguration.forClient(maximumTLSVersion: .tlsv12, certificateVerification: .none)
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      maximumTLSVersion: .tlsv12,
                                                      certificateVerification: .noHostnameVerification,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert2]))

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContainsAnyOf: ["ALERT_HANDSHAKE_FAILURE"])
    }

    func testMutualValidationRequiresClientCertificatePostTLS13() throws {
        let clientConfig = TLSConfiguration.forClient(minimumTLSVersion: .tlsv13, certificateVerification: .none)
        let serverConfig = TLSConfiguration.forServer(certificateChain: [.certificate(TLSConfigurationTest.cert1)],
                                                      privateKey: .privateKey(TLSConfigurationTest.key1),
                                                      minimumTLSVersion: .tlsv13,
                                                      certificateVerification: .noHostnameVerification,
                                                      trustRoots: .certificates([TLSConfigurationTest.cert2]))

        try assertPostHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContainsAnyOf: ["CERTIFICATE_REQUIRED"])
    }
    
    func testIncompatibleSignatures() throws {
        let clientConfig = TLSConfiguration.forClient(
            verifySignatureAlgorithms: [.ecdsaSecp384R1Sha384],
            minimumTLSVersion: .tlsv13,
            certificateVerification:.noHostnameVerification,
            trustRoots: .certificates([TLSConfigurationTest.cert1]),
            renegotiationSupport: .none
        )

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            signingSignatureAlgorithms: [.rsaPssRsaeSha256],
            minimumTLSVersion: .tlsv13,
            certificateVerification: .none)

        try assertHandshakeError(withClientConfig: clientConfig, andServerConfig: serverConfig, errorTextContains: "ALERT_HANDSHAKE_FAILURE")
    }

    func testCompatibleSignatures() throws {

        let clientConfig = TLSConfiguration.forClient(
            minimumTLSVersion: .tlsv13,
            certificateVerification:.noHostnameVerification,
            trustRoots: .certificates([TLSConfigurationTest.cert1])
        )

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            signingSignatureAlgorithms:  [.rsaPssRsaeSha256],
            minimumTLSVersion: .tlsv13,
            certificateVerification: .none)

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMatchingCompatibleSignatures() throws {

        let clientConfig = TLSConfiguration.forClient(
            verifySignatureAlgorithms: [.rsaPssRsaeSha256],
            minimumTLSVersion: .tlsv13,
            certificateVerification:.noHostnameVerification,
            trustRoots: .certificates([TLSConfigurationTest.cert1]),
            renegotiationSupport: .none
        )

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            signingSignatureAlgorithms: [.rsaPssRsaeSha256],
            minimumTLSVersion: .tlsv13,
            certificateVerification: .none)

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }


    func testMutualValidationSuccessNoAdditionalTrustRoots() throws {
        let clientConfig = TLSConfiguration.forClient(
            certificateVerification:.noHostnameVerification,
            trustRoots: .certificates([TLSConfigurationTest.cert1]),
            renegotiationSupport: .none)

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1))

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationSuccessWithDefaultAndAdditionalTrustRoots() throws {
        let clientConfig = TLSConfiguration.forClient(
            certificateVerification:.noHostnameVerification,
            trustRoots: .default,
            renegotiationSupport: .none,
            additionalTrustRoots: [.certificates([TLSConfigurationTest.cert1])])

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            trustRoots: .default,
            additionalTrustRoots: [.certificates([TLSConfigurationTest.cert2])])

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationSuccessWithOnlyAdditionalTrustRoots() throws {
        let clientConfig = TLSConfiguration.forClient(
            certificateVerification:.noHostnameVerification,
            trustRoots: .certificates([]),
            renegotiationSupport: .none,
            additionalTrustRoots: [.certificates([TLSConfigurationTest.cert1])])

        let serverConfig = TLSConfiguration.forServer(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            trustRoots: .certificates([]),
            additionalTrustRoots: [.certificates([TLSConfigurationTest.cert2])])

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testNonexistentFileObject() throws {
        let clientConfig = TLSConfiguration.forClient(trustRoots: .file("/thispathbetternotexist/bogus.foo"))

        XCTAssertThrowsError(try NIOSSLContext(configuration: clientConfig)) {error in
            XCTAssertEqual(.noSuchFilesystemObject, error as? NIOSSLError)
        }
    }

    func testComputedApplicationProtocols() throws {
        var config = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"])
        XCTAssertEqual(config.applicationProtocols, ["http/1.1"])
        XCTAssertEqual(config.encodedApplicationProtocols, [[8, 104, 116, 116, 112, 47, 49, 46, 49]])
        config.applicationProtocols.insert("h2", at: 0)
        XCTAssertEqual(config.applicationProtocols, ["h2", "http/1.1"])
        XCTAssertEqual(config.encodedApplicationProtocols, [[2, 104, 50], [8, 104, 116, 116, 112, 47, 49, 46, 49]])
    }

    func testKeyLogManagerOverlappingAccess() throws {
        // Tests that we can have overlapping calls to the log() function of the keylog manager.
        // This test fails probabilistically! DO NOT IGNORE INTERMITTENT FAILURES OF THIS TEST.
        let semaphore = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        let completionsQueue = DispatchQueue(label: "completionsQueue")
        var completions: [Bool] = []

        func keylogCallback(_ ign: ByteBuffer) {
            completionsQueue.sync {
                completions.append(true)
                semaphore.wait()
            }
            group.leave()
        }

        let keylogManager = KeyLogCallbackManager(callback: keylogCallback(_:))

        // Now we call log twice, from different threads. These will not complete right away so we
        // do those on background threads. They should not both complete.
        group.enter()
        group.enter()
        DispatchQueue(label: "first-thread").async {
            keylogManager.log("hello!")
        }
        DispatchQueue(label: "second-thread").async {
            keylogManager.log("world!")
        }

        // We now sleep a short time to let everything catch up and the runtime catch any exclusivity violation.
        // 10ms is fine.
        usleep(10_000)

        // Great, signal the sempahore twice to un-wedge everything and wait for everything to exit.
        semaphore.signal()
        semaphore.signal()
        group.wait()
        XCTAssertEqual([true, true], completionsQueue.sync { completions })
    }
    
    func testTheSameHashValue() {
        let config = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"])
        let theSameConfig  = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"])
        var hasher = Hasher()
        var hasher2 = Hasher()
        config.bestEffortHash(into: &hasher)
        theSameConfig.bestEffortHash(into: &hasher2)
        XCTAssertEqual(hasher.finalize(), hasher2.finalize())
        XCTAssertTrue(config.bestEffortEquals(theSameConfig))
    }
    
    func testDifferentHashValues() {
        let config = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"])
        let differentConfig = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake2.file"), applicationProtocols: ["http/1.1"])
        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }
    
    func testDifferentCallbacksNotEqual() {
        let config = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"], keyLogCallback: { _ in })
        let differentConfig = TLSConfiguration.forServer(certificateChain: [], privateKey: .file("fake.file"), applicationProtocols: ["http/1.1"], keyLogCallback: { _ in })
        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }
}
