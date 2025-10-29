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

@_implementationOnly import CNIOBoringSSL
@preconcurrency import Dispatch
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOTLS
import XCTest

@testable import NIOSSL

final class ErrorCatcher<T: Error>: ChannelInboundHandler, Sendable {
    public typealias InboundIn = Any
    let _errors: NIOLockedValueBox<[T]>
    var errors: [T] {
        self._errors.withLockedValue { $0 }
    }

    public init() {
        self._errors = .init([])
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        self._errors.withLockedValue { $0.append(error as! T) }
    }
}

final class HandshakeCompletedHandler: ChannelInboundHandler, Sendable {
    public typealias InboundIn = Any
    let _handshakeSucceeded = NIOLockedValueBox(false)
    var handshakeSucceeded: Bool {
        self._handshakeSucceeded.withLockedValue { $0 }
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? TLSUserEvent, case .handshakeCompleted = event {
            self._handshakeSucceeded.withLockedValue { $0 = true }
        }
        context.fireUserInboundEventTriggered(event)
    }
}

final class WaitForHandshakeHandler: ChannelInboundHandler, Sendable {
    public typealias InboundIn = Any
    public var handshakeResult: EventLoopFuture<Void> {
        self.handshakeResultPromise.futureResult
    }

    private let handshakeResultPromise: EventLoopPromise<Void>

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
    static let _certAndKey1 = generateSelfSignedCert()
    static let cert1 = TLSConfigurationTest._certAndKey1.0
    static let key1 = TLSConfigurationTest._certAndKey1.1

    static let _certAndKey2 = generateSelfSignedCert()
    static let cert2 = TLSConfigurationTest._certAndKey2.0
    static let key2 = TLSConfigurationTest._certAndKey2.1

    func assertHandshakeError(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        errorTextContains message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: [message],
            file: file,
            line: line
        )
    }

    func assertHandshakeError(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        errorTextContainsAnyOf messages: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig),
            file: file,
            line: line
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig),
            file: file,
            line: line
        )

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<NIOSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(
            serverTLSChannel(context: serverContext, handlers: [], group: group),
            file: file,
            line: line
        )
        let clientChannel = try assertNoThrowWithValue(
            clientTLSChannel(
                context: clientContext,
                preHandlers: [],
                postHandlers: [eventHandler, handshakeHandler],
                group: group,
                connectingTo: serverChannel.localAddress!
            ),
            file: file,
            line: line
        )

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

    func assertPostHandshakeError(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        errorTextContainsAnyOf messages: [String],
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig),
            file: file,
            line: line
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig),
            file: file,
            line: line
        )

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<BoringSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let serverChannel = try assertNoThrowWithValue(
            serverTLSChannel(context: serverContext, handlers: [], group: group),
            file: file,
            line: line
        )
        let clientChannel = try assertNoThrowWithValue(
            clientTLSChannel(
                context: clientContext,
                preHandlers: [],
                postHandlers: [eventHandler, handshakeHandler],
                group: group,
                connectingTo: serverChannel.localAddress!
            ),
            file: file,
            line: line
        )

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
    func assertHandshakeSucceededInMemory(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        try self.assertHandshakeSucceededInMemory(
            withClientContext: clientContext,
            andServerContext: serverContext,
            file: file,
            line: line
        )
    }

    /// Performs a connection in memory and validates that the handshake was successful.
    ///
    /// - NOTE: This function should only be used when you know that there is no custom verification
    /// callback in use, otherwise it will not be thread-safe.
    func assertHandshakeSucceededInMemory(
        withClientContext clientContext: NIOSSLContext,
        andServerContext serverContext: NIOSSLContext,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server case to throw
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: serverContext)),
            file: (file),
            line: line
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: clientContext, serverHostname: nil)
            ),
            file: (file),
            line: line
        )
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
    func assertHandshakeSucceededEventLoop(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        serverCustomVerificationCallback: (
            @Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) ->
                Void
        )? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig),
            file: file,
            line: line
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig),
            file: file,
            line: line
        )
        try self.assertHandshakeSucceededEventLoop(
            withClientContext: clientContext,
            andServerContext: serverContext,
            serverCustomVerificationCallback: serverCustomVerificationCallback,
            file: file,
            line: line
        )
    }

    /// Performs a connection using a real event loop and validates that the handshake was successful.
    ///
    /// This function is thread-safe in the presence of custom verification callbacks.
    func assertHandshakeSucceededEventLoop(
        withClientContext clientContext: NIOSSLContext,
        andServerContext serverContext: NIOSSLContext,
        serverCustomVerificationCallback: (
            @Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) ->
                Void
        )? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let eventHandler = ErrorCatcher<BoringSSLError>()
        let handshakeHandler = HandshakeCompletedHandler()
        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)

        let serverChannel = try assertNoThrowWithValue(
            serverTLSChannel(
                context: serverContext,
                handlers: [],
                group: group,
                customVerificationCallback: serverCustomVerificationCallback
            ),
            file: file,
            line: line
        )
        let clientChannel = try assertNoThrowWithValue(
            clientTLSChannel(
                context: clientContext,
                preHandlers: [],
                postHandlers: [eventHandler, handshakeWatcher, handshakeHandler],
                group: group,
                connectingTo: serverChannel.localAddress!
            ),
            file: file,
            line: line
        )

        handshakeWatcher.handshakeResult.whenComplete { c in
            _ = clientChannel.close()
        }

        clientChannel.closeFuture.whenComplete { _ in
            XCTAssertEqual(eventHandler.errors.count, 0, file: file, line: line)
            XCTAssertTrue(handshakeHandler.handshakeSucceeded, file: file, line: line)
        }
        try clientChannel.closeFuture.wait()
    }

    func assertHandshakeSucceeded(
        withClientConfig clientConfig: TLSConfiguration,
        andServerConfig serverConfig: TLSConfiguration,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        // The only use of a custom callback is on Darwin...
        #if os(Linux)
        return try assertHandshakeSucceededInMemory(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            file: file,
            line: line
        )

        #else
        return try assertHandshakeSucceededEventLoop(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            file: file,
            line: line
        )
        #endif
    }

    func assertHandshakeSucceeded(
        withClientContext clientContext: NIOSSLContext,
        andServerContext serverContext: NIOSSLContext,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        // The only use of a custom callback is on Darwin...
        #if os(Linux)
        return try self.assertHandshakeSucceededInMemory(
            withClientContext: clientContext,
            andServerContext: serverContext,
            file: file,
            line: line
        )

        #else
        return try self.assertHandshakeSucceededEventLoop(
            withClientContext: clientContext,
            andServerContext: serverContext,
            file: file,
            line: line
        )
        #endif
    }

    func setupTLSLeafandClientIdentitiesFromCustomCARoot() throws -> (
        leafCert: NIOSSLCertificate, leafKey: NIOSSLPrivateKey,
        clientCert: NIOSSLCertificate, clientKey: NIOSSLPrivateKey
    ) {
        let leaf = try NIOSSLCertificate(bytes: .init(leafCertificateForTLSIssuedFromCustomCARoot.utf8), format: .pem)
        let leaf_privateKey = try NIOSSLPrivateKey.init(bytes: .init(privateKeyForLeafCertificate.utf8), format: .pem)

        let client_cert = try NIOSSLCertificate(
            bytes: .init(leafCertificateForClientAuthenticationIssuedFromCustomCARoot.utf8),
            format: .pem
        )
        let client_privateKey = try NIOSSLPrivateKey.init(
            bytes: .init(privateKeyForClientAuthentication.utf8),
            format: .pem
        )
        return (leaf, leaf_privateKey, client_cert, client_privateKey)
    }

    // Note that this is a stub to create the rehash file format for a certificate.
    // If needed in the future the numericExtension should be reworked to check for duplicates and increment as applicable.
    func getRehashFilename(path: String, testName: String, numericExtension: Int) -> String {
        var cert: NIOSSLCertificate!
        if path.suffix(4) == ".pem" {
            XCTAssertNoThrow(cert = try NIOSSLCertificate.fromPEMFile(path).first)
        } else {
            XCTAssertNoThrow(cert = try NIOSSLCertificate.fromDERFile(path))
        }
        // Create a rehash format filename to symlink the hard file above to.
        let originalSubjectName = cert.getSubjectNameHash()
        let truncatedHash = String(format: "%08lx.%d", originalSubjectName, numericExtension)
        let tempDirPath = FileManager.default.temporaryDirectory.path + "/" + testName + "/"
        return tempDirPath + truncatedHash
    }

    func testNonOverlappingTLSVersions() throws {
        var clientConfig = TLSConfiguration.clientDefault
        clientConfig.minimumTLSVersion = .tlsv11
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.maximumTLSVersion = .tlsv1

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_PROTOCOL_VERSION"
        )
    }

    func testNonOverlappingCipherSuitesPreTLS13() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_RSA_WITH_AES_128_CBC_SHA]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [.TLS_RSA_WITH_AES_256_CBC_SHA]
        serverConfig.maximumTLSVersion = .tlsv12

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testCannotVerifySelfSigned() throws {
        let clientConfig = TLSConfiguration.makeClientConfiguration()
        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "CERTIFICATE_VERIFY_FAILED"
        )
    }

    func testServerCannotValidateClientPreTLS13() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key2)

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .noHostnameVerification

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["ALERT_UNKNOWN_CA", "ALERT_CERTIFICATE_UNKNOWN"]
        )
    }

    func testServerCannotValidateClientPostTLS13() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key2)

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .noHostnameVerification

        try assertPostHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["ALERT_UNKNOWN_CA", "ALERT_CERTIFICATE_UNKNOWN"]
        )
    }

    func testMutualValidationWithCertVerificationOptionalSuccess_NoPeerCert() throws {
        // The client doesn't present a cert chain
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        // The server sets `certificateVerification` to `optionalVerification`; handshake should succeed when the client
        // hasn't presented any certs
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationWithCertVerificationOptionalError_PeerCertNotTrusted() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key2)
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default
        // The server doesn't trust any additional roots; the cert presented by the client will not be trusted
        serverConfig.additionalTrustRoots = []

        try assertPostHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["SSLV3_ALERT_CERTIFICATE_UNKNOWN", "TLSV1_ALERT_UNKNOWN_CA"]
        )
    }

    func testMutualValidationWithCertVerificationOptionalSuccess_PeerCertTrusted() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key2)
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default
        // The server trusts the cert presented by the client; we expect a successful handshake
        serverConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert2])]

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationRequiresClientCertificatePreTLS13() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .noHostnameVerification
        serverConfig.trustRoots = .certificates([TLSConfigurationTest.cert2])

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["ALERT_HANDSHAKE_FAILURE"]
        )
    }

    func testMutualValidationRequiresClientCertificatePostTLS13() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.certificateVerification = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .noHostnameVerification
        serverConfig.trustRoots = .certificates([TLSConfigurationTest.cert2])

        try assertPostHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["CERTIFICATE_REQUIRED"]
        )
    }

    func testIncompatibleSignatures() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.verifySignatureAlgorithms = [.ecdsaSecp384R1Sha384]
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.signingSignatureAlgorithms = [.rsaPssRsaeSha256]
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .none

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testCompatibleSignatures() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.signingSignatureAlgorithms = [.rsaPssRsaeSha256]
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMatchingCompatibleSignatures() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.verifySignatureAlgorithms = [.rsaPssRsaeSha256]
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.signingSignatureAlgorithms = [.rsaPssRsaeSha256]
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationSuccessNoAdditionalTrustRoots() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationSuccessWithDefaultAndAdditionalTrustRoots() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.renegotiationSupport = .none
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.trustRoots = .default
        serverConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert2])]

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMutualValidationSuccessWithOnlyAdditionalTrustRoots() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([])
        clientConfig.renegotiationSupport = .none
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.trustRoots = .certificates([])
        serverConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert2])]

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testFullVerificationWithCANamesFromCertificate() throws {
        // Custom certificates for TLS and client authentication.
        let root = try NIOSSLCertificate(bytes: .init(customCARoot.utf8), format: .pem)

        let digitalIdentities = try setupTLSLeafandClientIdentitiesFromCustomCARoot()

        // Client Configuration.
        //
        // This configuration disables hostname verification because the hostname verification
        // code requires IP addresses, which we don't have in EmbeddedChannel. We override the
        // trust roots to prevent execution of the SecurityFramework verification code, which doesn't
        // work with EmbeddedChannel.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.renegotiationSupport = .none
        clientConfig.certificateChain = [.certificate(digitalIdentities.clientCert)]
        clientConfig.privateKey = .privateKey(digitalIdentities.clientKey)
        clientConfig.trustRoots = .certificates([root])
        clientConfig.certificateVerification = .noHostnameVerification

        // Server Configuration
        //
        // This configuration disables hostname verification because the hostname verification
        // code requires IP addresses, which we don't have in EmbeddedChannel. We override the
        // trust roots to prevent execution of the SecurityFramework verification code, which doesn't
        // work with EmbeddedChannel.
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(digitalIdentities.leafCert)],
            privateKey: .privateKey(digitalIdentities.leafKey)
        )
        serverConfig.sendCANameList = true
        serverConfig.trustRoots = .certificates([root])
        serverConfig.certificateVerification = .noHostnameVerification

        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))

        // Validation that the CA names are being sent here
        // This is essentially the heart of this unit test.
        let countAfter = serverContext.getX509NameListCount()
        XCTAssertEqual(countAfter, 1, "CA Name List should be 1 after the Server Context is created")

        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server case to throw
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: serverContext))
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: clientContext, serverHostname: nil)
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a successful handshake.
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        clientChannel.connect(to: addr, promise: nil)
        serverChannel.pipeline.fireChannelActive()
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        serverChannel.close(promise: nil)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

    }

    func testFullVerificationWithCANamesFromFile() throws {
        // Custom certificates for TLS and client authentication.
        // In this test create the root certificate in the tmp directory and use it here to send the CA names.
        // This exercised the loadVerifyLocations file code path out in SSLContext
        let rootPath = try dumpToFile(data: .init(customCARoot.utf8), fileExtension: ".pem")

        let digitalIdentities = try setupTLSLeafandClientIdentitiesFromCustomCARoot()

        // Client Configuration.
        //
        // This configuration disables hostname verification because the hostname verification
        // code requires IP addresses, which we don't have in EmbeddedChannel. We override the
        // trust roots to prevent execution of the SecurityFramework verification code, which doesn't
        // work with EmbeddedChannel.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.renegotiationSupport = .none
        clientConfig.certificateChain = [.certificate(digitalIdentities.clientCert)]
        clientConfig.privateKey = .privateKey(digitalIdentities.clientKey)
        clientConfig.trustRoots = .file(rootPath)
        clientConfig.certificateVerification = .noHostnameVerification

        // Server Configuration
        //
        // This configuration disables hostname verification because the hostname verification
        // code requires IP addresses, which we don't have in EmbeddedChannel. We override the
        // trust roots to prevent execution of the SecurityFramework verification code, which doesn't
        // work with EmbeddedChannel.
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(digitalIdentities.leafCert)],
            privateKey: .privateKey(digitalIdentities.leafKey)
        )
        serverConfig.sendCANameList = true
        serverConfig.trustRoots = .file(rootPath)
        serverConfig.certificateVerification = .noHostnameVerification

        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))

        // Validation that the CA names are being sent here
        // This is essentially the heart of this unit test.
        let countAfter = serverContext.getX509NameListCount()
        XCTAssertEqual(countAfter, 1, "CA Name List should be 1 after the Server Context is created")

        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server case to throw
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: serverContext))
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: clientContext, serverHostname: nil)
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        clientChannel.connect(to: addr, promise: nil)
        serverChannel.pipeline.fireChannelActive()
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        serverChannel.close(promise: nil)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + rootPath)!))
    }

    func testRehashFormatToPopulateCANamesFromDirectory() throws {
        // Use the test name as the directory name in the temporary directory.
        let testName = String("\(#function)".dropLast(2))
        // Create 2 PEM based certs
        let rootCAPathOne = try dumpToFile(data: .init(customCARoot.utf8), fileExtension: ".pem", customPath: testName)
        let rootCAPathTwo = try dumpToFile(
            data: .init(secondaryRootCertificateForClientAuthentication.utf8),
            fileExtension: ".pem",
            customPath: testName
        )

        // Create a rehash formatted name of both certificate's subject name that was created above.
        // Take these rehash certificate names and format a symlink with them below with createSymbolicLink.
        let rehashSymlinkNameOne = getRehashFilename(path: rootCAPathOne, testName: testName, numericExtension: 0)
        let rehashSymlinkNameTwo = getRehashFilename(path: rootCAPathTwo, testName: testName, numericExtension: 0)
        // Extract just the filename of the newly create certs in the tmp directory.
        let rootCAURLOne = URL(string: "file://" + rootCAPathOne)!
        let rootCAURLTwo = URL(string: "file://" + rootCAPathTwo)!
        let rootCAFilenameOne = rootCAURLOne.lastPathComponent
        let rootCAFilenameTwo = rootCAURLTwo.lastPathComponent

        // Create an in-directory symlink the same way that c_rehash would do this.
        // For example: 7f44456a.0 -> niotestIEOFcMI.pem
        // NOT: 7f44456a.0 -> /var/folders/my/path/niotestIEOFcMI.pem
        XCTAssertNoThrow(
            try FileManager.default.createSymbolicLink(
                atPath: rehashSymlinkNameOne,
                withDestinationPath: rootCAFilenameOne
            )
        )
        XCTAssertNoThrow(
            try FileManager.default.createSymbolicLink(
                atPath: rehashSymlinkNameTwo,
                withDestinationPath: rootCAFilenameTwo
            )
        )

        defer {
            // Delete all files that were created for this test.
            XCTAssertNoThrow(try FileManager.default.removeItem(at: rootCAURLOne))
            XCTAssertNoThrow(try FileManager.default.removeItem(at: rootCAURLTwo))
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + rehashSymlinkNameOne)!))
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + rehashSymlinkNameTwo)!))
            // Remove the actual directory also.
            let removePath = "\(FileManager.default.temporaryDirectory.path)/\(testName)/"
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + removePath)!))
        }

        let tempFileDir = FileManager.default.temporaryDirectory.path + "/\(testName)/"
        let digitalIdentities = try setupTLSLeafandClientIdentitiesFromCustomCARoot()

        // Server Configuration
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(digitalIdentities.leafCert)],
            privateKey: .privateKey(digitalIdentities.leafKey)
        )
        serverConfig.sendCANameList = true
        serverConfig.trustRoots = .file(tempFileDir)  // Directory path.
        serverConfig.certificateVerification = .fullVerification

        var serverContext: NIOSSLContext!
        XCTAssertNoThrow(serverContext = try NIOSSLContext(configuration: serverConfig))
        // Only setup the serverContext here to define that our two certificate CA names were populated to the SSL_CTX.
        let countAfter = serverContext.getX509NameListCount()
        XCTAssertEqual(countAfter, 2, "CA Name List should be 2 after the Server Context is created")
    }

    func testRehashFormat() throws {
        // Use the test name as the directory name in the temporary directory.
        let testName = String("\(#function)".dropLast(2))
        // This test case creates path variables and files to run through the `isRehashFormat` function in `NIOSSLContext`.
        // Note that the c_rehash file format is a symlink to an original PEM or CER file in the form of HHHHHHHH.D.
        // Note that CRLs are not supported, only PEM and DER representations of certificates.

        // Not a valid path.
        let badPath = try NIOSSLContext._isRehashFormat(path: "")
        XCTAssertFalse(badPath)
        // Filename is not in rehash format.
        let acceptablePathBadFilename = try NIOSSLContext._isRehashFormat(path: "/etc/ssl/certs/myFile.pem")
        XCTAssertFalse(acceptablePathBadFilename)
        // Filename is in bad rehash format.
        let acceptablePathBadRehashFormat = try NIOSSLContext._isRehashFormat(path: "/etc/ssl/certs/7f44456a.z")
        XCTAssertFalse(acceptablePathBadRehashFormat)

        // Test with an actual file, but no symlink.
        let dummyFile = try dumpToFile(data: Data(), fileExtension: ".txt", customPath: testName)
        let newPath = FileManager.default.temporaryDirectory.path + "/\(testName)/7f44456a.1"
        let _ = try FileManager.default.moveItem(atPath: dummyFile, toPath: newPath)
        // Filename is in rehash format, but not a symlink.
        let acceptablePathAndRehashFormatButNoSymlink = try NIOSSLContext._isRehashFormat(path: newPath)
        XCTAssertFalse(acceptablePathAndRehashFormatButNoSymlink)

        // Test actual symlink
        let rootCAPathOne = try dumpToFile(data: .init(customCARoot.utf8), fileExtension: ".pem", customPath: testName)
        let rehashSymlinkName = getRehashFilename(path: rootCAPathOne, testName: testName, numericExtension: 0)

        // Extract just the filename of the newly create certs in the tmp directory.
        let rootCAURLOne = URL(string: "file://" + rootCAPathOne)!
        let rootCAFilenameOne = rootCAURLOne.lastPathComponent

        XCTAssertNoThrow(
            try FileManager.default.createSymbolicLink(
                atPath: rehashSymlinkName,
                withDestinationPath: rootCAFilenameOne
            )
        )

        defer {
            // Delete all files that were created for this test.
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + rootCAPathOne)!))
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + rehashSymlinkName)!))
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + newPath)!))
            // Remove the actual directory also.
            let removePath = "\(FileManager.default.temporaryDirectory.path)/\(testName)/"
            XCTAssertNoThrow(try FileManager.default.removeItem(at: URL(string: "file://" + removePath)!))
        }

        // Test the success case for the symlink
        let successSymlink = try NIOSSLContext._isRehashFormat(path: rehashSymlinkName)
        XCTAssertTrue(successSymlink)
    }

    func testNonexistentFileObject() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.trustRoots = .file("/thispathbetternotexist/bogus.foo")

        XCTAssertThrowsError(try NIOSSLContext(configuration: clientConfig)) { error in
            XCTAssertEqual(.noSuchFilesystemObject, error as? NIOSSLError)
        }
    }

    func testComputedApplicationProtocols() throws {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        config.applicationProtocols = ["http/1.1"]
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
        let completions: UnsafeMutableTransferBox<[Bool]> = .init([])

        let keylogManager = KeyLogCallbackManager { _ in
            completionsQueue.sync {
                completions.wrappedValue.append(true)
                semaphore.wait()
            }
            group.leave()
        }

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
        XCTAssertEqual([true, true], completionsQueue.sync { completions.wrappedValue })
    }

    func testTheSameHashValue() {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        config.applicationProtocols = ["http/1.1"]
        let theSameConfig = config
        var hasher = Hasher()
        var hasher2 = Hasher()
        config.bestEffortHash(into: &hasher)
        theSameConfig.bestEffortHash(into: &hasher2)
        XCTAssertEqual(hasher.finalize(), hasher2.finalize())
        XCTAssertTrue(config.bestEffortEquals(theSameConfig))
    }

    func testDifferentHashValues() {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        config.applicationProtocols = ["http/1.1"]
        var differentConfig = config
        differentConfig.privateKey = .privateKey(TLSConfigurationTest.key2)
        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }

    func testDifferentCallbacksNotEqual() {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        config.applicationProtocols = ["http/1.1"]
        config.keyLogCallback = { _ in }
        var differentConfig = config
        differentConfig.keyLogCallback = { _ in }
        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }

    func testDifferentSSLContextCallbacksNotEqual() throws {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        config.applicationProtocols = ["http/1.1"]
        config.sslContextCallback = { _, _ in }
        var differentConfig = config
        differentConfig.sslContextCallback = { _, _ in }
        XCTAssertFalse(config.bestEffortEquals(differentConfig))
    }

    func testCompatibleCurves() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.x25519]
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        serverConfig.curves = [.x25519]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMultipleCompatibleCurves() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.x25519]
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.curves = [.x25519, .secp256r1]
        serverConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testNonCompatibleCurves() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.secp521r1]
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.curves = [.x25519]
        serverConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testPQCompatibleCurves() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.x25519_MLKEM768]
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.curves = [.x25519_MLKEM768]
        serverConfig.certificateVerification = .none
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testDefaultCurvesExcludePQ() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.x25519_MLKEM768]
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .none
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testUnknownCurveValuesFail() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.curves = [.init(rawValue: 0x9898)]

        XCTAssertThrowsError(try NIOSSLContext(configuration: clientConfig)) { error in
            XCTAssertTrue(
                String(describing: error).contains("UNSUPPORTED_ELLIPTIC_CURVE"),
                "Error \(error) does not contain UNSUPPORTED_ELLIPTIC_CURVE"
            )
        }
    }

    func testCompatibleCipherSuite() throws {
        // ECDHE_RSA is used here because the public key in .cert1 is derived from a RSA private key.
        // These could also be RSA based, but cannot be ECDHE_ECDSA.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testNonCompatibleCipherSuite() throws {
        // This test fails more importantly because ECDHE_ECDSA is being set with a public key that is RSA based.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_RSA_WITH_AES_128_GCM_SHA256]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testDefaultWithRSACipherSuite() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_RSA_WITH_AES_128_GCM_SHA256]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuites = defaultCipherSuites
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testDefaultWithECDHERSACipherSuite() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuites = defaultCipherSuites
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testStringBasedCipherSuite() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuites = "AES256"
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuites = "AES256"
        serverConfig.maximumTLSVersion = .tlsv12

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMultipleCompatibleCipherSuites() throws {
        // This test is for multiple ECDHE_RSA based ciphers on the server side.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMultipleCompatibleCipherSuitesWithStringBasedCipher() throws {
        // This test is for using multiple server side ciphers with the client side string based cipher.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuites = "AES256"
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuiteValues = [
            .TLS_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        ]
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testMultipleClientCipherSuitesWithDefaultCipher() throws {
        // Client ciphers should match one of the default ciphers.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [
            .TLS_RSA_WITH_AES_128_CBC_SHA,
            .TLS_RSA_WITH_AES_256_CBC_SHA,
            .TLS_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_CHACHA20_POLY1305_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            .TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuites = defaultCipherSuites
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.certificateVerification = .none

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testNonCompatibleClientCiphersWithServerStringBasedCiphers() throws {
        // This test should fail on client hello negotiation.
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.cipherSuites = "AES256"
        serverConfig.maximumTLSVersion = .tlsv12

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "ALERT_HANDSHAKE_FAILURE"
        )
    }

    func testSettingCiphersWithCipherSuiteValues() {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuiteValues = [
            .TLS_AES_128_GCM_SHA256,
            .TLS_AES_256_GCM_SHA384,
            .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.renegotiationSupport = .none

        XCTAssertEqual(
            clientConfig.cipherSuites,
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        )
    }

    func testSettingCiphersWithCipherSuitesString() {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.cipherSuites = "AES256"
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        let assignedCiphers = clientConfig.cipherSuiteValues.map { $0.standardName }
        let createdCipherSuiteValuesFromString = assignedCiphers.joined(separator: ":")
        // Note that this includes the PSK values as well.
        XCTAssertEqual(
            createdCipherSuiteValuesFromString,
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_PSK_WITH_AES_256_CBC_SHA"
        )
    }

    func testDefaultCipherSuiteValues() {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([])
        clientConfig.renegotiationSupport = .none
        clientConfig.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])]
        XCTAssertEqual(clientConfig.cipherSuites, defaultCipherSuites)

        let assignedCiphers = clientConfig.cipherSuiteValues.map { $0.standardName }
        let defaultCipherSuiteValuesFromString = assignedCiphers.joined(separator: ":")
        // Note that this includes the PSK values as well.
        XCTAssertEqual(
            defaultCipherSuiteValuesFromString,
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA"
        )
    }

    @available(
        *,
        deprecated,
        message: "`TLSConfiguration.pskClientCallback` and `TLSConfiguration.pskClientCallback` are deprecated"
    )
    func testBestEffortEquatableHashableDifferences() {
        // If this assertion fails, DON'T JUST CHANGE THE NUMBER HERE! Make sure you've added any appropriate transforms below
        // so that we're testing these best effort functions.
        XCTAssertEqual(
            MemoryLayout<TLSConfiguration>.size,
            234,
            "TLSConfiguration has changed size: you probably need to update this test!"
        )

        let first = TLSConfiguration.makeClientConfiguration()

        let pskClientCallback: NIOPSKClientIdentityCallback = { (hint: String) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerCallback: NIOPSKServerIdentityCallback = {
            (hint: String, identity: String) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        let sslContextCallback: NIOSSLContextCallback = { _, _ in }

        let transforms: [(inout TLSConfiguration) -> Void] = [
            { $0.minimumTLSVersion = .tlsv13 },
            { $0.maximumTLSVersion = .tlsv12 },
            { $0.cipherSuites = "AES" },
            { $0.curves = [.x25519] },
            { $0.cipherSuiteValues = [.TLS_RSA_WITH_AES_256_CBC_SHA] },
            { $0.verifySignatureAlgorithms = [.ed25519] },
            { $0.signingSignatureAlgorithms = [.ed25519] },
            { $0.certificateVerification = .noHostnameVerification },
            { $0.trustRoots = .certificates([TLSConfigurationTest.cert1]) },
            { $0.additionalTrustRoots = [.certificates([TLSConfigurationTest.cert1])] },
            { $0.certificateChain = [.certificate(TLSConfigurationTest.cert1)] },
            { $0.privateKey = .privateKey(TLSConfigurationTest.key1) },
            { $0.applicationProtocols = ["h2"] },
            { $0.shutdownTimeout = .seconds((60 * 24 * 24) + 1) },
            { $0.keyLogCallback = { _ in } },
            { $0.renegotiationSupport = .always },
            { $0.sendCANameList = true },
            { $0.pskClientCallback = pskClientCallback },
            { $0.pskServerCallback = pskServerCallback },
            { $0.sslContextCallback = sslContextCallback },
            { $0.pskServerCallback = pskServerCallback },
            { $0.pskClientProvider = pskClientProvider },
            { $0.pskServerProvider = pskServerProvider },
            { $0.pskHint = "hint" },
        ]

        for (index, transform) in transforms.enumerated() {
            var transformed = first
            transform(&transformed)
            XCTAssertNotEqual(
                Wrapper(config: first),
                Wrapper(config: transformed),
                "Should have compared not equal in index \(index)"
            )
            XCTAssertEqual(
                Set([Wrapper(config: first), Wrapper(config: transformed)]).count,
                2,
                "Should have hashed non-equal in index \(index)"
            )
        }
    }

    func testObtainingTLSVersionOnClientChannel() throws {
        let b2b = BackToBackEmbeddedChannel()

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.maximumTLSVersion = .tlsv11
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.maximumTLSVersion = .tlsv11
        serverConfig.certificateVerification = .none

        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        XCTAssertNoThrow(
            try b2b.client.pipeline.syncOperations.addHandlers(
                [
                    try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"),
                    HandshakeCompletedHandler(),
                ]
            )
        )
        XCTAssertNoThrow(
            try b2b.server.pipeline.syncOperations.addHandlers(
                [NIOSSLServerHandler(context: serverContext), HandshakeCompletedHandler()]
            )
        )
        XCTAssertNoThrow(try b2b.connectInMemory())
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)

        var tlsVersion: TLSVersion?
        XCTAssertNoThrow(tlsVersion = try b2b.client.pipeline.syncOperations.nioSSL_tlsVersion())
        XCTAssertEqual(tlsVersion!, .tlsv11)

        let tlsVersionForChannel = b2b.client.nioSSL_tlsVersion()
        var channelTLSVersion: TLSVersion?
        XCTAssertNoThrow(channelTLSVersion = try tlsVersionForChannel.wait())
        XCTAssertEqual(channelTLSVersion!, .tlsv11)
    }

    @available(
        *,
        deprecated,
        message: "`TLSConfiguration.pskClientCallback` and `TLSConfiguration.pskClientCallback` are deprecated"
    )
    func testTLSPSKWithTLS13Deprecated() throws {
        // The idea here is that adding PSKs with certificates in TLS 1.3 should NOT cause a failure.
        // Also note that the usage here of PSKs with TLS 1.3 is not supported by BoringSSL at this point.
        let pskClientCallback: NIOPSKClientIdentityCallback = { (hint: String) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerCallback: NIOPSKServerIdentityCallback = {
            (hint: String, identity: String) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            XCTAssertEqual(identity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.trustRoots = .certificates([])
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.maximumTLSVersion = .tlsv13
        clientConfig.pskClientCallback = pskClientCallback
        clientConfig.pskHint = "clientPskHint"

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.maximumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .none
        serverConfig.pskServerCallback = pskServerCallback
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    @available(
        *,
        deprecated,
        message: "`TLSConfiguration.pskClientCallback` and `TLSConfiguration.pskClientCallback` are deprecated"
    )
    func testTLSPSKWithTLS12Deprecated() throws {
        // This test ensures that PSK-TLS is supported for TLS 1.2.
        let pskClientCallback: NIOPSKClientIdentityCallback = { (hint: String) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerCallback: NIOPSKServerIdentityCallback = {
            (hint: String, identity: String) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            XCTAssertEqual(identity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskHint = "clientPskHint"
        clientConfig.pskClientCallback = pskClientCallback

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerCallback = pskServerCallback
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    @available(
        *,
        deprecated,
        message: "`TLSConfiguration.pskClientCallback` and `TLSConfiguration.pskClientCallback` are deprecated"
    )
    func testTLSPSKWithPinnedCiphersDeprecated() throws {
        // This test ensures that PSK-TLS is supported with pinned ciphers.
        let pskClientCallback: NIOPSKClientIdentityCallback = { (hint: String) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerCallback: NIOPSKServerIdentityCallback = {
            (hint: String, identity: String) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            XCTAssertEqual(identity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientCallback = pskClientCallback
        clientConfig.pskHint = "clientPskHint"
        clientConfig.cipherSuiteValues = [
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_PSK_WITH_AES_128_CBC_SHA,
            .TLS_PSK_WITH_AES_256_CBC_SHA,
        ]

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerCallback = pskServerCallback
        serverConfig.pskHint = "serverPskHint"
        serverConfig.cipherSuiteValues = [
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_PSK_WITH_AES_128_CBC_SHA,
            .TLS_PSK_WITH_AES_256_CBC_SHA,
        ]
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    @available(
        *,
        deprecated,
        message: "`TLSConfiguration.pskClientCallback` and `TLSConfiguration.pskClientCallback` are deprecated"
    )
    func testTLSPSKFailureDeprecated() throws {
        // This test ensures that different PSKs used on the client and server fail when passed in.
        let pskClientCallback: NIOPSKClientIdentityCallback = { (hint: String) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerCallback: NIOPSKServerIdentityCallback = {
            (hint: String, identity: String) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(hint, "serverPskHint")
            XCTAssertEqual(identity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("server".utf8)  // Failure
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientCallback = pskClientCallback
        clientConfig.pskHint = "clientPskHint"

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerCallback = pskServerCallback
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["SSLV3_ALERT_BAD_RECORD_MAC"]
        )
    }

    @available(*, deprecated, message: "`.file` NIOSSLPrivateKeySource option deprecated")
    func testUnknownPrivateKeyFileType() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.privateKey = .file("key.invalidExtension")

        XCTAssertThrowsError(try NIOSSLContext(configuration: clientConfig)) { error in
            guard let sslError = error as? NIOSSLExtraError else {
                return XCTFail("Expected NIOSSLExtraError but got \(error)")
            }

            XCTAssertEqual(sslError, .unknownPrivateKeyFileType)
        }
    }

    func testTLSPSKWithTLS13() throws {
        // The idea here is that adding PSKs with certificates in TLS 1.3 should NOT cause a failure.
        // Also note that the usage here of PSKs with TLS 1.3 is not supported by BoringSSL at this point.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            XCTAssertEqual(context.clientIdentity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.trustRoots = .certificates([])
        clientConfig.minimumTLSVersion = .tlsv13
        clientConfig.maximumTLSVersion = .tlsv13
        clientConfig.pskClientProvider = pskClientProvider
        clientConfig.pskHint = "clientPskHint"

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.minimumTLSVersion = .tlsv13
        serverConfig.maximumTLSVersion = .tlsv13
        serverConfig.certificateVerification = .none
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testTLSPSKWithTLS12() throws {
        // This test ensures that PSK-TLS is supported for TLS 1.2.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            XCTAssertEqual(context.clientIdentity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskHint = "clientPskHint"
        clientConfig.pskClientProvider = pskClientProvider

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testTLSPSKWithPinnedCiphers() throws {
        // This test ensures that PSK-TLS is supported with pinned ciphers.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            XCTAssertEqual(context.clientIdentity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientProvider = pskClientProvider
        clientConfig.pskHint = "clientPskHint"
        clientConfig.cipherSuiteValues = [
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_PSK_WITH_AES_128_CBC_SHA,
            .TLS_PSK_WITH_AES_256_CBC_SHA,
        ]

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = "serverPskHint"
        serverConfig.cipherSuiteValues = [
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            .TLS_PSK_WITH_AES_128_CBC_SHA,
            .TLS_PSK_WITH_AES_256_CBC_SHA,
        ]
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testTLSPSKFailure() throws {
        // This test ensures that different PSKs used on the client and server fail when passed in.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Evaluate hint and clientIdentity to send back proper PSK.
            XCTAssertEqual(context.hint, "serverPskHint")
            XCTAssertEqual(context.clientIdentity, "world")
            var psk = NIOSSLSecureBytes()
            psk.append("server".utf8)  // Failure
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientProvider = pskClientProvider
        clientConfig.pskHint = "clientPskHint"

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = "serverPskHint"
        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["SSLV3_ALERT_BAD_RECORD_MAC"]
        )
    }

    func testTLSPSKNoServerHint() throws {
        let pseudoExpectation = ConditionLock(value: false)
        // This test ensures that different PSKs used on the client and server fail when passed in.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            pseudoExpectation.lock()
            pseudoExpectation.unlock(withValue: true)
            // Ensure server hint is nil
            XCTAssertEqual(context.hint, nil)
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Ensure server hint is nil
            XCTAssertEqual(context.hint, nil)
            XCTAssertEqual(context.clientIdentity, "world")
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)  // Failure
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientProvider = pskClientProvider
        clientConfig.pskHint = "clientPskHint"

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = nil
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
        XCTAssertTrue(pseudoExpectation.lock(whenValue: true, timeoutSeconds: 1))
        pseudoExpectation.unlock()
    }

    func testTLSPSKNoClientHint() throws {
        let pseudoExpectation = ConditionLock(value: false)
        // This test ensures that different PSKs used on the client and server fail when passed in.
        let pskClientProvider: NIOPSKClientIdentityProvider = {
            (context: PSKClientContext) -> PSKClientIdentityResponse in
            pseudoExpectation.lock()
            pseudoExpectation.unlock(withValue: true)
            // Ensure server hint is nil
            XCTAssertEqual(context.hint, nil)
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)
            return PSKClientIdentityResponse(key: psk, identity: "world")
        }

        let pskServerProvider: NIOPSKServerIdentityProvider = {
            (context: PSKServerContext) -> PSKServerIdentityResponse in
            // Ensure server hint is nil
            XCTAssertEqual(context.hint, nil)
            XCTAssertEqual(context.clientIdentity, "world")
            // Evaluate hint and clientIdentity to send back proper PSK.
            var psk = NIOSSLSecureBytes()
            psk.append("hello".utf8)  // Failure
            return PSKServerIdentityResponse(key: psk)
        }

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.minimumTLSVersion = .tlsv1
        clientConfig.maximumTLSVersion = .tlsv12
        clientConfig.pskClientProvider = pskClientProvider
        clientConfig.pskHint = nil

        var serverConfig = TLSConfiguration.makePreSharedKeyConfiguration()
        serverConfig.minimumTLSVersion = .tlsv1
        serverConfig.maximumTLSVersion = .tlsv12
        serverConfig.pskServerProvider = pskServerProvider
        serverConfig.pskHint = nil
        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
        XCTAssertTrue(pseudoExpectation.lock(whenValue: true, timeoutSeconds: 1))
        pseudoExpectation.unlock()
    }

    func testClientSideCertSelection() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
            override.privateKey = .privateKey(TLSConfigurationTest.key2)
            promise.succeed(override)
        }

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .noHostnameVerification
        serverConfig.trustRoots = .certificates([TLSConfigurationTest.cert2])

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    /// This test ensures that, when a certificate is overriden, only the new chain is sent, not the previous one.
    /// This test would have failed prior to the commit in which it was added.
    func testClientSideCertSelectionWithChain() throws {
        let (testIntermediate, _) = generateSelfSignedCert()
        let (testLeaf, privateKey) = generateSelfSignedCert()
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateChain = [.certificate(testLeaf), .certificate(testIntermediate)]
        clientConfig.privateKey = .privateKey(privateKey)

        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        // This callback should be a no-op, it returns the same certs we had already set anyway
        clientConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(testLeaf), .certificate(testIntermediate)]
            override.privateKey = .privateKey(privateKey)
            promise.succeed(override)
        }

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .noHostnameVerification

        try assertHandshakeSucceededEventLoop(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            serverCustomVerificationCallback: { certificates, promise in
                XCTAssertEqual(certificates.count, 2)
                XCTAssertEqual(certificates, [testLeaf, testIntermediate])
                // Always succeed for the purposes of this test
                promise.succeed(.certificateVerified)
            }
        )
    }

    func testServerSideCertSelection() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert2)],
            privateKey: .privateKey(TLSConfigurationTest.key2)
        )
        serverConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(TLSConfigurationTest.cert1)]
            override.privateKey = .privateKey(TLSConfigurationTest.key1)
            promise.succeed(override)
        }

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testOverrideWithNothingIsFine() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.sslContextCallback = { _, promise in
            let `override` = NIOSSLContextConfigurationOverride()
            promise.succeed(override)
        }

        try assertHandshakeSucceeded(withClientConfig: clientConfig, andServerConfig: serverConfig)
    }

    func testOverrideToInvalidCertFailsHandshake() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert2)],
            privateKey: .privateKey(TLSConfigurationTest.key2)
        )
        serverConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(TLSConfigurationTest.cert1)]
            promise.succeed(override)
        }

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "TLSV1_ALERT_INTERNAL_ERROR"
        )
    }

    func testOverrideToInvalidKeyFailsHandshake() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.privateKey = .privateKey(TLSConfigurationTest.key2)
            promise.succeed(override)
        }

        try assertHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContains: "TLSV1_ALERT_INTERNAL_ERROR"
        )
    }

    func testClientSideCertSelection_eachConnectionSelectsAgain() throws {
        let callbackCount = NIOLockedValueBox(0)
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.sslContextCallback = { _, promise in
            callbackCount.withLockedValue { $0 += 1 }

            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
            override.privateKey = .privateKey(TLSConfigurationTest.key2)
            promise.succeed(override)
        }

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1)
        )
        serverConfig.certificateVerification = .noHostnameVerification
        serverConfig.trustRoots = .certificates([TLSConfigurationTest.cert2])

        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig)
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig)
        )

        for _ in 0..<5 {
            try assertHandshakeSucceeded(withClientContext: clientContext, andServerContext: serverContext)
        }

        XCTAssertEqual(callbackCount.withLockedValue { $0 }, 5)
    }

    func testServerSideCertSelection_eachConnectionSelectsAgain() throws {
        let callbackCount = NIOLockedValueBox(0)
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert2)],
            privateKey: .privateKey(TLSConfigurationTest.key2)
        )
        serverConfig.sslContextCallback = { _, promise in
            var `override` = NIOSSLContextConfigurationOverride()
            override.certificateChain = [.certificate(TLSConfigurationTest.cert1)]
            override.privateKey = .privateKey(TLSConfigurationTest.key1)
            callbackCount.withLockedValue { $0 += 1 }
            promise.succeed(override)
        }

        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig)
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig)
        )

        for _ in 0..<5 {
            try assertHandshakeSucceeded(withClientContext: clientContext, andServerContext: serverContext)
        }

        XCTAssertEqual(callbackCount.withLockedValue { $0 }, 5)
    }

    func testCorrectSetUpOfMTLSContext() throws {
        var basicConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(TLSConfigurationTest.cert2)],
            privateKey: .privateKey(TLSConfigurationTest.key2)
        )
        let mtlsConfig = TLSConfiguration.makeServerConfigurationWithMTLS(
            certificateChain: [.certificate(TLSConfigurationTest.cert2)],
            privateKey: .privateKey(TLSConfigurationTest.key2),
            trustRoots: .default
        )
        XCTAssertFalse(basicConfig.bestEffortEquals(mtlsConfig))

        basicConfig.trustRoots = .default
        basicConfig.certificateVerification = .noHostnameVerification

        XCTAssertTrue(basicConfig.bestEffortEquals(mtlsConfig))
    }

    func testMTLSContext_happyPath() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert2)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key2)
        clientConfig.certificateVerification = .noHostnameVerification

        let serverConfig = TLSConfiguration.makeServerConfigurationWithMTLS(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            trustRoots: .certificates([TLSConfigurationTest.cert2])
        )

        let clientContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: clientConfig)
        )
        let serverContext = try assertNoThrowWithValue(
            NIOSSLContext(configuration: serverConfig)
        )

        try assertHandshakeSucceeded(withClientContext: clientContext, andServerContext: serverContext)
    }

    func testMTLSContext_clientPresentsWrongCert() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.trustRoots = .certificates([TLSConfigurationTest.cert1])
        clientConfig.certificateChain = [.certificate(TLSConfigurationTest.cert1)]
        clientConfig.privateKey = .privateKey(TLSConfigurationTest.key1)
        clientConfig.certificateVerification = .noHostnameVerification

        let serverConfig = TLSConfiguration.makeServerConfigurationWithMTLS(
            certificateChain: [.certificate(TLSConfigurationTest.cert1)],
            privateKey: .privateKey(TLSConfigurationTest.key1),
            trustRoots: .certificates([TLSConfigurationTest.cert2])
        )

        try assertPostHandshakeError(
            withClientConfig: clientConfig,
            andServerConfig: serverConfig,
            errorTextContainsAnyOf: ["ALERT_UNKNOWN_CA", "ALERT_CERTIFICATE_UNKNOWN"]
        )
    }
}

extension EmbeddedChannel {
    fileprivate var handshakeSucceeded: Bool {
        let completedHandler = try! self.pipeline.syncOperations.handler(type: HandshakeCompletedHandler.self)
        return completedHandler.handshakeSucceeded
    }
}

struct Wrapper: Hashable {
    var config: TLSConfiguration

    static func == (lhs: Wrapper, rhs: Wrapper) -> Bool {
        lhs.config.bestEffortEquals(rhs.config)
    }

    func hash(into hasher: inout Hasher) {
        self.config.bestEffortHash(into: &hasher)
    }
}
