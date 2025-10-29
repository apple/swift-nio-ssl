//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSL

// This is a helper that lets us work with an EVP_PKEY.
//
// This type is thread-safe: it doesn't perform any mutation of the underlying object.
private final class CustomPKEY: @unchecked Sendable {
    private let ref: OpaquePointer

    init(from key: NIOSSLPrivateKey) {
        // Extract a copy of the key reference here.
        self.ref = key.withUnsafeMutableEVPPKEYPointer { pkey in
            CNIOBoringSSL_EVP_PKEY_up_ref(pkey)
            return pkey
        }
    }

    init(from generator: () -> OpaquePointer) {
        self.ref = generator()
    }

    deinit {
        CNIOBoringSSL_EVP_PKEY_free(self.ref)
    }

    func sign(algorithm: SignatureAlgorithm, data: ByteBuffer) -> ByteBuffer {
        let ctx = CNIOBoringSSL_EVP_PKEY_CTX_new(self.ref, nil)!
        defer {
            CNIOBoringSSL_EVP_PKEY_CTX_free(ctx)
        }

        // Step 1: We need to hash the input before we sign.
        let hashContext = CNIOBoringSSL_EVP_MD_CTX_new()!
        defer {
            CNIOBoringSSL_EVP_MD_CTX_free(hashContext)
        }
        CNIOBoringSSL_EVP_MD_CTX_init(hashContext)
        CNIOBoringSSL_EVP_DigestInit_ex(hashContext, algorithm.md, nil)
        var rc = data.withUnsafeReadableBytes { bytesPtr in
            CNIOBoringSSL_EVP_DigestUpdate(
                hashContext,
                bytesPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                bytesPtr.count
            )
        }
        precondition(rc == 1)

        let signatureSize = CNIOBoringSSL_EVP_MD_size(algorithm.md)

        var digestBuffer = ByteBuffer()
        digestBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes: signatureSize) { outputPtr in
            var actualSize = CUnsignedInt(outputPtr.count)
            CNIOBoringSSL_EVP_DigestFinal_ex(
                hashContext,
                outputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                &actualSize
            )
            return Int(actualSize)
        }

        // Ok, great, we've hashed. Now let's do the signing.
        precondition(CNIOBoringSSL_EVP_PKEY_sign_init(ctx) == 1)
        // TODO: Add RSA padding when needed.
        CNIOBoringSSL_EVP_PKEY_CTX_set_signature_md(ctx, algorithm.md)

        // For RSA algorithms we may need to add padding.
        if let padding = algorithm.rsaPadding {
            CNIOBoringSSL_EVP_PKEY_CTX_set_rsa_padding(ctx, padding)
        }

        // And for some RSA padding, that may require a salt.
        if let saltLength = algorithm.saltLen {
            CNIOBoringSSL_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltLength)
        }

        // Now we find out the length we need.
        var signatureLength: Int = 0
        rc = digestBuffer.withUnsafeReadableBytes { bytesPtr in
            CNIOBoringSSL_EVP_PKEY_sign(
                ctx,
                nil,
                &signatureLength,
                bytesPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                bytesPtr.count
            )
        }

        precondition(rc == 1)

        // And finally we can do the sign.
        var outputBuffer = ByteBuffer()
        outputBuffer.writeWithUnsafeMutableBytes(minimumWritableBytes: signatureLength) { outputPtr in
            precondition(signatureLength <= outputPtr.count)
            let rc = digestBuffer.withUnsafeReadableBytes { bytesPtr in
                CNIOBoringSSL_EVP_PKEY_sign(
                    ctx,
                    outputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &signatureLength,
                    bytesPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    bytesPtr.count
                )
            }
            precondition(rc == 1)
            return signatureLength
        }

        return outputBuffer
    }

    func decrypt(data: ByteBuffer) -> ByteBuffer {
        // Decryption is only needed for RSA, so this has to work.
        let rsa = CNIOBoringSSL_EVP_PKEY_get0_RSA(self.ref)!
        let targetSize = CNIOBoringSSL_RSA_size(rsa)

        var output = ByteBuffer()
        output.writeWithUnsafeMutableBytes(minimumWritableBytes: Int(targetSize)) { outputBytes in
            var written = 0
            let rc = data.withUnsafeReadableBytes { inputBytes in
                CNIOBoringSSL_RSA_decrypt(
                    rsa,
                    &written,
                    outputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    outputBytes.count,
                    inputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    inputBytes.count,
                    RSA_NO_PADDING
                )
            }
            precondition(rc == 1)
            return written
        }

        return output
    }
}

private final class CustomKeyImmediateResult: NIOSSLCustomPrivateKey, Hashable {
    let backing: CustomPKEY
    let signatureAlgorithms: [SignatureAlgorithm]
    let expectedChannel: Channel
    let _signCallCount: NIOLockedValueBox<Int>
    let _decryptCallCount: NIOLockedValueBox<Int>

    var signCallCount: Int {
        self._signCallCount.withLockedValue { $0 }
    }

    var decryptCallCount: Int {
        self._decryptCallCount.withLockedValue { $0 }
    }

    fileprivate init(_ backing: CustomPKEY, signatureAlgorithms: [SignatureAlgorithm], expectedChannel: Channel) {
        self.backing = backing
        self.signatureAlgorithms = signatureAlgorithms
        self.expectedChannel = expectedChannel
        self._signCallCount = .init(0)
        self._decryptCallCount = .init(0)
    }

    func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        XCTAssertTrue(channel === self.expectedChannel)
        XCTAssertTrue(self.signatureAlgorithms.contains(algorithm))
        self._signCallCount.withLockedValue { $0 += 1 }
        return channel.eventLoop.makeSucceededFuture(self.backing.sign(algorithm: algorithm, data: data))
    }

    func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        XCTAssertTrue(channel === self.expectedChannel)
        self._decryptCallCount.withLockedValue { $0 += 1 }
        return channel.eventLoop.makeSucceededFuture(self.backing.decrypt(data: data))
    }

    static func == (lhs: CustomKeyImmediateResult, rhs: CustomKeyImmediateResult) -> Bool {
        lhs.backing === rhs.backing && lhs.signatureAlgorithms == rhs.signatureAlgorithms
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self.backing))
        hasher.combine(signatureAlgorithms)
    }
}

private final class CustomKeyDelayedCompletion: NIOSSLCustomPrivateKey, Hashable {
    let backing: CustomPKEY
    let signatureAlgorithms: [SignatureAlgorithm]
    let expectedChannel: Channel
    let _pendingSigningEvents: NIOLockedValueBox<[EventLoopPromise<Void>]>
    let _pendingDecryptionEvents: NIOLockedValueBox<[EventLoopPromise<Void>]>

    var pendingSigningEvents: [EventLoopPromise<Void>] {
        self._pendingSigningEvents.withLockedValue { $0 }
    }
    var pendingDecryptionEvents: [EventLoopPromise<Void>] {
        self._pendingDecryptionEvents.withLockedValue { $0 }
    }

    fileprivate init(_ backing: CustomPKEY, signatureAlgorithms: [SignatureAlgorithm], expectedChannel: Channel) {
        self.backing = backing
        self.signatureAlgorithms = signatureAlgorithms
        self.expectedChannel = expectedChannel
        self._pendingSigningEvents = .init([])
        self._pendingDecryptionEvents = .init([])
    }

    func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        XCTAssertTrue(channel === self.expectedChannel)
        XCTAssertTrue(self.signatureAlgorithms.contains(algorithm))

        let promise = channel.eventLoop.makePromise(of: Void.self)
        self._pendingSigningEvents.withLockedValue { $0.append(promise) }
        return promise.futureResult.map {
            self.backing.sign(algorithm: algorithm, data: data)
        }
    }

    func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        XCTAssertTrue(channel === self.expectedChannel)

        let promise = channel.eventLoop.makePromise(of: Void.self)
        self._pendingDecryptionEvents.withLockedValue { $0.append(promise) }
        return promise.futureResult.map {
            self.backing.decrypt(data: data)
        }
    }

    static func == (lhs: CustomKeyDelayedCompletion, rhs: CustomKeyDelayedCompletion) -> Bool {
        lhs.backing === rhs.backing && lhs.signatureAlgorithms == rhs.signatureAlgorithms
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self.backing))
        hasher.combine(signatureAlgorithms)
    }
}

private final class CustomKeyWithoutDERBytes: NIOSSLCustomPrivateKey, Hashable {
    var signatureAlgorithms: [SignatureAlgorithm] { [] }

    func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        fatalError("Not implemented")
    }

    func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        fatalError("Not implemented")
    }

    static func == (lhs: CustomKeyWithoutDERBytes, rhs: CustomKeyWithoutDERBytes) -> Bool {
        lhs.signatureAlgorithms == rhs.signatureAlgorithms
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
        hasher.combine(signatureAlgorithms)
    }
}

private final class CustomKeyWithDERBytes: NIOSSLCustomPrivateKey, Hashable {
    var signatureAlgorithms: [NIOSSL.SignatureAlgorithm] { [] }

    var derBytes: [UInt8] { [42] }

    func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        fatalError("Not implemented")
    }

    func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        fatalError("Not implemented")
    }

    static func == (lhs: CustomKeyWithDERBytes, rhs: CustomKeyWithDERBytes) -> Bool {
        lhs.signatureAlgorithms == rhs.signatureAlgorithms && lhs.derBytes == rhs.derBytes
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
        hasher.combine(signatureAlgorithms)
        hasher.combine(derBytes)
    }
}

final class CustomPrivateKeyTests: XCTestCase {
    fileprivate static let customECDSACertAndKey: (certificate: NIOSSLCertificate, key: CustomPKEY) = {
        let (cert, originalKey) = generateSelfSignedCert(keygenFunction: {
            generateECPrivateKey(curveNID: NID_X9_62_prime256v1)
        })
        let derivedKey = CustomPKEY(from: originalKey)
        return (certificate: cert, key: derivedKey)
    }()

    fileprivate static let customRSACertAndKey: (certificate: NIOSSLCertificate, key: CustomPKEY) = {
        let (cert, originalKey) = generateSelfSignedCert()
        let derivedKey = CustomPKEY(from: originalKey)
        return (certificate: cert, key: derivedKey)
    }()

    private func configuredClientContext(
        trustRoot: NIOSSLCertificate,
        maxTLSVersion: TLSVersion? = nil,
        cipherSuites: [NIOTLSCipher]? = nil
    ) -> NIOSSLContext {
        var config = TLSConfiguration.makeClientConfiguration()
        config.trustRoots = .certificates([trustRoot])
        config.maximumTLSVersion = maxTLSVersion
        if let cipherSuites = cipherSuites {
            config.cipherSuiteValues = cipherSuites
        }
        return try! NIOSSLContext(configuration: config)
    }

    private func configuredServerContext(certificate: NIOSSLCertificate, privateKey: NIOSSLPrivateKey) -> NIOSSLContext
    {
        let config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        return try! NIOSSLContext(configuration: config)
    }

    func testHappyPathImmediateResultCustomECDSAKey() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyImmediateResult(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customECDSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customECDSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertEqual(happyPathKey.signCallCount, 1)
        XCTAssertEqual(happyPathKey.decryptCallCount, 0)
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testHappyPathImmediateResultCustomRSAKeyPSS() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyImmediateResult(
            CustomPrivateKeyTests.customRSACertAndKey.key,
            signatureAlgorithms: [.rsaPssRsaeSha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customRSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertEqual(happyPathKey.signCallCount, 1)
        XCTAssertEqual(happyPathKey.decryptCallCount, 0)
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testHappyPathImmediateResultCustomRSAKeyPKCS1() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyImmediateResult(
            CustomPrivateKeyTests.customRSACertAndKey.key,
            signatureAlgorithms: [.rsaPkcs1Sha256],
            expectedChannel: b2b.server
        )

        // Rule out TLSv1.3, which doesn't support RSA decryption.
        // We also want to force RSA key exchange, which will let us test the decrypt
        // function.
        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            maxTLSVersion: .tlsv12,
            cipherSuites: [.TLS_RSA_WITH_AES_128_GCM_SHA256]
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertEqual(happyPathKey.signCallCount, 0)
        XCTAssertEqual(happyPathKey.decryptCallCount, 1)
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testHappyPathDelayedResultCustomECDSAKey() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customECDSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customECDSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        // Complete the promise.
        XCTAssertEqual(happyPathKey.pendingSigningEvents.count, 1)
        XCTAssertEqual(happyPathKey.pendingDecryptionEvents.count, 0)
        happyPathKey.pendingSigningEvents.first?.succeed(())

        // Nothing happens until we start doing I/O again.
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        XCTAssertNoThrow(try b2b.interactInMemory())
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testHappyPathDelayedResultCustomRSAKeyPSS() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customRSACertAndKey.key,
            signatureAlgorithms: [.rsaPssRsaeSha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customRSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        // Complete the promise.
        XCTAssertEqual(happyPathKey.pendingSigningEvents.count, 1)
        XCTAssertEqual(happyPathKey.pendingDecryptionEvents.count, 0)
        happyPathKey.pendingSigningEvents.first?.succeed(())

        // Nothing happens until we start doing I/O again.
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        XCTAssertNoThrow(try b2b.interactInMemory())
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testHappyPathDelayedResultCustomRSAKeyPKCS1() throws {
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customRSACertAndKey.key,
            signatureAlgorithms: [.rsaPkcs1Sha256],
            expectedChannel: b2b.server
        )

        // Rule out TLSv1.3, which doesn't support RSA decryption.
        // We also want to force RSA key exchange, which will let us test the decrypt
        // function.
        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            maxTLSVersion: .tlsv12,
            cipherSuites: [.TLS_RSA_WITH_AES_128_GCM_SHA256]
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customRSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
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
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        // Complete the promise.
        XCTAssertEqual(happyPathKey.pendingSigningEvents.count, 0)
        XCTAssertEqual(happyPathKey.pendingDecryptionEvents.count, 1)
        happyPathKey.pendingDecryptionEvents.first?.succeed(())

        // Nothing happens until we start doing I/O again.
        XCTAssertFalse(b2b.client.handshakeSucceeded)
        XCTAssertFalse(b2b.server.handshakeSucceeded)

        XCTAssertNoThrow(try b2b.interactInMemory())
        XCTAssertTrue(b2b.client.handshakeSucceeded)
        XCTAssertTrue(b2b.server.handshakeSucceeded)
    }

    func testMismatchedKeys() throws {
        // We're going to generate another ECDSA key here, which we'll give to the backing code.
        let alternativeKey = generateSelfSignedCert(keygenFunction: { generateECPrivateKey() }).1
        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyImmediateResult(
            CustomPKEY(from: alternativeKey),
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customECDSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customECDSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
        XCTAssertNoThrow(
            try b2b.client.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
            )
        )
        XCTAssertNoThrow(
            try b2b.server.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: serverContext)
            )
        )

        XCTAssertThrowsError(try b2b.connectInMemory())
    }

    func testThrowingCustomErrorsSigning() throws {
        struct CustomError: Error {}

        let b2b = BackToBackEmbeddedChannel()
        let happyPathKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        let clientContext = self.configuredClientContext(
            trustRoot: CustomPrivateKeyTests.customECDSACertAndKey.certificate
        )
        let serverContext = self.configuredServerContext(
            certificate: CustomPrivateKeyTests.customECDSACertAndKey.certificate,
            privateKey: NIOSSLPrivateKey(customPrivateKey: happyPathKey)
        )
        XCTAssertNoThrow(
            try b2b.client.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
            )
        )
        XCTAssertNoThrow(
            try b2b.server.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: serverContext)
            )
        )

        XCTAssertNoThrow(try b2b.connectInMemory())

        // Complete the promise.
        XCTAssertEqual(happyPathKey.pendingSigningEvents.count, 1)
        XCTAssertEqual(happyPathKey.pendingDecryptionEvents.count, 0)
        happyPathKey.pendingSigningEvents.first?.fail(CustomError())

        XCTAssertThrowsError(try b2b.interactInMemory()) { error in
            XCTAssertTrue(error is CustomError)
        }
    }

    func testKeyEquatability() throws {
        let b2b = BackToBackEmbeddedChannel()

        let firstKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        // Should be non-equal to first
        let secondKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp384R1Sha384],
            expectedChannel: b2b.server
        )

        // Different object to first, but same equatable, so should be equal
        let thirdKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        XCTAssertEqual(firstKey, thirdKey)
        XCTAssertNotEqual(firstKey, secondKey)
        XCTAssertEqual(NIOSSLPrivateKey(customPrivateKey: firstKey), NIOSSLPrivateKey(customPrivateKey: thirdKey))
        XCTAssertNotEqual(NIOSSLPrivateKey(customPrivateKey: firstKey), NIOSSLPrivateKey(customPrivateKey: secondKey))
    }

    func testKeyHashability() throws {
        let b2b = BackToBackEmbeddedChannel()

        let firstKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        // Should hash non-equal to first
        let secondKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp384R1Sha384],
            expectedChannel: b2b.server
        )

        // Different object to first, but same hashable, so should hash the same
        let thirdKey = CustomKeyDelayedCompletion(
            CustomPrivateKeyTests.customECDSACertAndKey.key,
            signatureAlgorithms: [.ecdsaSecp256R1Sha256],
            expectedChannel: b2b.server
        )

        XCTAssertEqual(Set([firstKey, secondKey]), Set([firstKey, secondKey, thirdKey]))
        XCTAssertEqual(
            Set([NIOSSLPrivateKey(customPrivateKey: firstKey), NIOSSLPrivateKey(customPrivateKey: secondKey)]),
            Set([
                NIOSSLPrivateKey(customPrivateKey: firstKey), NIOSSLPrivateKey(customPrivateKey: secondKey),
                NIOSSLPrivateKey(customPrivateKey: thirdKey),
            ])
        )
    }

    func testDERBytes_DefaultImplementation_ReturnsEmptyArray() throws {
        let customKey = CustomKeyWithoutDERBytes()
        let key = NIOSSLPrivateKey(customPrivateKey: customKey)
        let derBytes = try key.derBytes
        XCTAssertEqual(derBytes, [])
    }

    func testDERBytes_ReturnsBytes() throws {
        let customKey = CustomKeyWithDERBytes()
        let key = NIOSSLPrivateKey(customPrivateKey: customKey)
        let derBytes = try key.derBytes
        XCTAssertEqual(derBytes, [42])
    }
}

extension SignatureAlgorithm {
    var md: OpaquePointer {
        switch self {
        case .ecdsaSecp256R1Sha256:
            return CNIOBoringSSL_EVP_sha256()
        case .rsaPssRsaeSha256:
            return CNIOBoringSSL_EVP_sha256()
        case .rsaPkcs1Sha256:
            return CNIOBoringSSL_EVP_sha256()
        default:
            preconditionFailure()
        }
    }

    var rsaPadding: CInt? {
        switch self {
        case .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512:
            return CInt(RSA_PKCS1_PSS_PADDING)
        case .rsaPkcs1Sha1, .rsaPkcs1Sha256, .rsaPkcs1Sha384, .rsaPkcs1Sha512:
            return CInt(RSA_PKCS1_PADDING)
        default:
            return nil
        }
    }

    var saltLen: CInt? {
        switch self {
        case .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512:
            // To BoringSSL, -1 means "salt length the size of the hash function".
            // This is what TLS 1.3 requires.
            return -1
        default:
            return nil
        }
    }
}

extension EmbeddedChannel {
    fileprivate var handshakeSucceeded: Bool {
        let completedHandler = try! self.pipeline.syncOperations.handler(type: HandshakeCompletedHandler.self)
        return completedHandler.handshakeSucceeded
    }
}
