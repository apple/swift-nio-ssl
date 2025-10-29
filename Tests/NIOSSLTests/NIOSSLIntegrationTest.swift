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
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOTLS
import XCTest

@testable import NIOSSL

public func assertNoThrowWithValue<T>(
    _ body: @autoclosure () throws -> T,
    defaultValue: T? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("unexpected error \(error) thrown", file: (file), line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

internal func interactInMemory(
    clientChannel: EmbeddedChannel,
    serverChannel: EmbeddedChannel,
    runLoops: Bool = true
) throws {
    var workToDo = true
    while workToDo {
        workToDo = false

        if runLoops {
            clientChannel.embeddedEventLoop.run()
            serverChannel.embeddedEventLoop.run()
        }

        let clientDatum = try clientChannel.readOutbound(as: IOData.self)
        let serverDatum = try serverChannel.readOutbound(as: IOData.self)

        if let clientMsg = clientDatum {
            try serverChannel.writeInbound(clientMsg)
            workToDo = true
        }

        if let serverMsg = serverDatum {
            try clientChannel.writeInbound(serverMsg)
            workToDo = true
        }
    }
}

private final class SimpleEchoServer: ChannelInboundHandler, Sendable {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
        context.fireChannelRead(data)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
        context.fireChannelReadComplete()
    }
}

internal final class PromiseOnReadHandler: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private let promise: EventLoopPromise<ByteBuffer>
    private var data: NIOAny? = nil

    init(promise: EventLoopPromise<ByteBuffer>) {
        self.promise = promise
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.data = data
        context.fireChannelRead(data)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        promise.succeed(unwrapInboundIn(data!))
        context.fireChannelReadComplete()
    }
}

private final class PromiseOnChildChannelInitHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<Channel>

    init(promise: EventLoopPromise<Channel>) {
        self.promise = promise
    }

    func channelActive(context: ChannelHandlerContext) {
        self.promise.succeed(context.channel)
        context.fireChannelActive()
    }
}

private final class ChannelInactiveHandler: ChannelInboundHandler, Sendable {
    typealias InboundIn = ByteBuffer
    private let promise: EventLoopPromise<Void>

    init(promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.promise.succeed()
        context.fireChannelActive()
    }
}

// Modified version taken from swift-nio/ChannelTests.swift
enum ShutDownEvent {
    case input
    case output
}

private final class ShutdownVerificationHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private var inputShutdownEventReceived = false
    private var outputShutdownEventReceived = false

    private let promise: EventLoopPromise<Void>
    private let shutdownEvent: ShutDownEvent

    init(shutdownEvent: ShutDownEvent, promise: EventLoopPromise<Void>) {
        self.promise = promise
        self.shutdownEvent = shutdownEvent
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let ev as ChannelEvent:
            switch ev {
            case .inputClosed:
                XCTAssertFalse(inputShutdownEventReceived)
                inputShutdownEventReceived = true

                if shutdownEvent == .input {
                    promise.succeed(())
                }
            case .outputClosed:
                XCTAssertFalse(outputShutdownEventReceived)
                outputShutdownEventReceived = true

                if shutdownEvent == .output {
                    promise.succeed(())
                }
            }

            fallthrough
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    public func channelInactive(context: ChannelHandlerContext) {
        switch shutdownEvent {
        case .input:
            XCTAssertTrue(inputShutdownEventReceived)
            XCTAssertFalse(outputShutdownEventReceived)
        case .output:
            XCTAssertFalse(inputShutdownEventReceived)
            XCTAssertTrue(outputShutdownEventReceived)
        }

        promise.succeed(())
        context.fireChannelInactive()
    }
}

private final class ReadRecordingHandler: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer

    private var received: ByteBuffer?
    private let completePromise: EventLoopPromise<ByteBuffer>

    init(completePromise: EventLoopPromise<ByteBuffer>) {
        self.completePromise = completePromise
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var data = self.unwrapInboundIn(data)

        var newBuffer: ByteBuffer
        if var received = self.received {
            received.writeBuffer(&data)
            newBuffer = received
        } else {
            newBuffer = data
        }

        self.received = newBuffer
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.completePromise.succeed(self.received ?? context.channel.allocator.buffer(capacity: 0))
    }
}

private final class WriteCountingHandler: ChannelOutboundHandler, Sendable {
    public typealias OutboundIn = Any
    public typealias OutboundOut = Any

    public var writeCount: Int {
        self._writeCount.withLockedValue { $0 }
    }
    private let _writeCount: NIOLockedValueBox<Int> = .init(0)

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        self._writeCount.withLockedValue { $0 += 1 }
        context.write(data, promise: promise)
    }
}

public final class EventRecorderHandler<UserEventType>: ChannelInboundHandler where UserEventType: Equatable {
    public typealias InboundIn = ByteBuffer

    public enum RecordedEvents: Equatable {
        case Registered
        case Unregistered
        case Active
        case Inactive
        case Read
        case ReadComplete
        case WritabilityChanged
        case UserEvent(UserEventType)
        // Note that this omits ErrorCaught. This is because Error does not
        // require Equatable, so we can't safely record these events and expect
        // a sensible implementation of Equatable here.

        public static func == (lhs: RecordedEvents, rhs: RecordedEvents) -> Bool {
            switch (lhs, rhs) {
            case (.Registered, .Registered),
                (.Unregistered, .Unregistered),
                (.Active, .Active),
                (.Inactive, .Inactive),
                (.Read, .Read),
                (.ReadComplete, .ReadComplete),
                (.WritabilityChanged, .WritabilityChanged):
                return true
            case (.UserEvent(let e1), .UserEvent(let e2)):
                return e1 == e2
            default:
                return false
            }
        }
    }

    public var events: [RecordedEvents] {
        self._events.withLockedValue { $0 }
    }
    private let _events: NIOLockedValueBox<[RecordedEvents]> = .init([])

    public func channelRegistered(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.Registered) }
        context.fireChannelRegistered()
    }

    public func channelUnregistered(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.Unregistered) }
        context.fireChannelUnregistered()
    }

    public func channelActive(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.Active) }
        context.fireChannelActive()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.Inactive) }
        context.fireChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self._events.withLockedValue { $0.append(.Read) }
        context.fireChannelRead(data)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.ReadComplete) }
        context.fireChannelReadComplete()
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        self._events.withLockedValue { $0.append(.WritabilityChanged) }
        context.fireChannelWritabilityChanged()
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        guard let ourEvent = event as? UserEventType else {
            context.fireUserInboundEventTriggered(event)
            return
        }
        self._events.withLockedValue { $0.append(.UserEvent(ourEvent)) }
    }
}

extension EventRecorderHandler: Sendable where UserEventType: Sendable {}

extension EventRecorderHandler.RecordedEvents: Sendable where UserEventType: Sendable {}

private final class ChannelActiveWaiter: ChannelInboundHandler, Sendable {
    public typealias InboundIn = Any

    private let activePromise: EventLoopPromise<Void>

    public init(promise: EventLoopPromise<Void>) {
        activePromise = promise
    }

    public func channelActive(context: ChannelHandlerContext) {
        activePromise.succeed(())
    }

    public func waitForChannelActive() throws {
        try activePromise.futureResult.wait()
    }
}

/// A channel handler that delays all writes that it receives. This is useful
/// in tests that want to ensure that writes propagate through the system in order.
///
/// Note that you must call forceFlush to pass all the data through, or your tests will
/// explode.
private class WriteDelayHandler: ChannelOutboundHandler {
    public typealias OutboundIn = Any
    public typealias OutboundOut = Any

    private var writes: [(ChannelHandlerContext, NIOAny, EventLoopPromise<Void>?)] = []

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writes.append((context, data, promise))
    }

    func forceFlush() {
        let writes = self.writes
        self.writes = []
        for write in writes { write.0.writeAndFlush(write.1, promise: write.2) }
    }
}

internal func serverTLSChannel(
    context: NIOSSLContext,
    handlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    customVerificationCallback: (
        @Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) ->
            Void
    )? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel {
    try assertNoThrowWithValue(
        serverTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: handlers(),
            group: group,
            customVerificationCallback: customVerificationCallback,
            file: file,
            line: line
        ),
        file: file,
        line: line
    )
}

internal func serverTLSChannel(
    context: NIOSSLContext,
    preHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    postHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    customVerificationCallback: (
        @Sendable ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) ->
            Void
    )? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel {
    try assertNoThrowWithValue(
        ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(preHandlers())

                    let handler: NIOSSLHandler
                    if let verify = customVerificationCallback {
                        handler = NIOSSLServerHandler(context: context, customVerificationCallback: verify)
                    } else {
                        handler = NIOSSLServerHandler(context: context)
                    }
                    try channel.pipeline.syncOperations.addHandler(handler)

                    try channel.pipeline.syncOperations.addHandlers(postHandlers())
                }
            }.bind(host: "127.0.0.1", port: 0).wait(),
        file: file,
        line: line
    )
}

typealias SendableAdditionalPeerCertificateVerificationCallback =
    @Sendable (NIOSSLCertificate, Channel) -> EventLoopFuture<Void>

internal func clientTLSChannel(
    context: NIOSSLContext,
    additionalPeerCertificateVerificationCallback: SendableAdditionalPeerCertificateVerificationCallback? = nil,
    preHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    postHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    connectingTo: SocketAddress,
    serverHostname: String? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel {
    func tlsFactory() -> NIOSSLClientTLSProvider<ClientBootstrap> {
        try! .init(
            context: context,
            serverHostname: serverHostname,
            additionalPeerCertificateVerificationCallback: additionalPeerCertificateVerificationCallback
        )
    }

    return try _clientTLSChannel(
        context: context,
        preHandlers: preHandlers,
        postHandlers: postHandlers,
        group: group,
        connectingTo: connectingTo,
        tlsFactory: tlsFactory
    )
}

@available(*, deprecated, message: "just for testing the deprecated functionality")
private struct DeprecatedTLSProviderForTests<Bootstrap: NIOClientTCPBootstrapProtocol>: NIOClientTLSProvider, Sendable {
    public typealias Bootstrap = Bootstrap

    let context: NIOSSLContext
    let serverHostname: String?
    let verificationCallback: @Sendable (NIOSSLVerificationResult, NIOSSLCertificate) -> NIOSSLVerificationResult

    @available(*, deprecated, renamed: "init(context:serverHostname:customVerificationCallback:)")
    public init(
        context: NIOSSLContext,
        serverHostname: String?,
        verificationCallback:
            @escaping @Sendable (NIOSSLVerificationResult, NIOSSLCertificate) ->
            NIOSSLVerificationResult
    ) {
        self.context = context
        self.serverHostname = serverHostname
        self.verificationCallback = verificationCallback
    }

    public func enableTLS(_ bootstrap: Bootstrap) -> Bootstrap {
        bootstrap.protocolHandlers { [context, serverHostname, verificationCallback] in
            // NIOSSLClientHandler.init only throws because of `malloc` error and invalid SNI hostnames. We want to crash
            // on malloc error and we pre-checked the SNI hostname in `init` so that should be impossible here.
            [
                try! NIOSSLClientHandler(
                    context: context,
                    serverHostname: serverHostname,
                    verificationCallback: verificationCallback
                )
            ]
        }
    }
}

@available(
    *,
    deprecated,
    renamed:
        "clientTLSChannel(context:preHandlers:postHandlers:group:connectingTo:serverHostname:customVerificationCallback:file:line:)"
)
internal func clientTLSChannel(
    context: NIOSSLContext,
    preHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    postHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    connectingTo: SocketAddress,
    serverHostname: String? = nil,
    verificationCallback: @escaping @Sendable (NIOSSLVerificationResult, NIOSSLCertificate) -> NIOSSLVerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel {
    func tlsFactory() -> DeprecatedTLSProviderForTests<ClientBootstrap> {
        .init(context: context, serverHostname: serverHostname, verificationCallback: verificationCallback)
    }

    return try _clientTLSChannel(
        context: context,
        preHandlers: preHandlers,
        postHandlers: postHandlers,
        group: group,
        connectingTo: connectingTo,
        tlsFactory: tlsFactory
    )
}

internal func clientTLSChannel(
    context: NIOSSLContext,
    preHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    postHandlers: @autoclosure @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    connectingTo: SocketAddress,
    serverHostname: String? = nil,
    customVerificationCallback: CustomCallback,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel {
    func tlsFactory() -> NIOSSLClientTLSProvider<ClientBootstrap> {
        try! .init(
            context: context,
            serverHostname: serverHostname,
            customVerificationCallback: customVerificationCallback
        )
    }

    return try _clientTLSChannel(
        context: context,
        preHandlers: preHandlers,
        postHandlers: postHandlers,
        group: group,
        connectingTo: connectingTo,
        tlsFactory: tlsFactory
    )
}

private func _clientTLSChannel<TLS: NIOClientTLSProvider>(
    context: NIOSSLContext,
    preHandlers: @escaping @Sendable () -> [ChannelHandler],
    postHandlers: @escaping @Sendable () -> [ChannelHandler],
    group: EventLoopGroup,
    connectingTo: SocketAddress,
    tlsFactory: @escaping () -> TLS,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> Channel where TLS.Bootstrap == ClientBootstrap {
    let bootstrap = NIOClientTCPBootstrap(
        ClientBootstrap(group: group),
        tls: tlsFactory()
    )
    return try assertNoThrowWithValue(
        bootstrap
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(postHandlers())
                }
            }
            .enableTLS()
            .connect(to: connectingTo)
            .flatMap { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(preHandlers(), position: .first)
                    return channel
                }
            }
            .wait(),
        file: file,
        line: line
    )
}

struct EventLoopFutureTimeoutError: Error {}

extension EventLoopFuture {
    func timeout(after failDelay: TimeAmount) -> EventLoopFuture<Value> {
        let promise = self.eventLoop.makePromise(of: Value.self)

        self.whenComplete { result in
            switch result {
            case .success(let value):
                promise.assumeIsolated().succeed(value)
            case .failure(let error):
                promise.fail(error)
            }
        }

        self.eventLoop.scheduleTask(in: failDelay) {
            promise.fail(EventLoopFutureTimeoutError())
        }

        return promise.futureResult
    }
}

class NIOSSLIntegrationTest: XCTestCase {
    private static let certAndKey = generateSelfSignedCert()
    static var cert: NIOSSLCertificate { Self.certAndKey.0 }
    static var key: NIOSSLPrivateKey { Self.certAndKey.1 }

    override class func setUp() {
        super.setUp()
        guard boringSSLIsInitialized else { fatalError() }
    }

    private static func withEncryptedKeyPath<ReturnType>(
        _ body: (String) throws -> ReturnType
    ) throws -> ReturnType {
        let path = try keyInFile(
            key: NIOSSLIntegrationTest.key,
            passphrase: "thisisagreatpassword"
        )
        defer {
            unlink(path)
        }
        return try body(path)
    }

    private func configuredSSLContext(
        keyLogCallback: NIOSSLKeyLogCallback? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        config.trustRoots = .certificates([NIOSSLIntegrationTest.cert])
        config.keyLogCallback = keyLogCallback
        return try assertNoThrowWithValue(NIOSSLContext(configuration: config), file: file, line: line)
    }

    private func configuredClientContext(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var config = TLSConfiguration.makeClientConfiguration()
        config.trustRoots = .certificates([NIOSSLIntegrationTest.cert])
        return try assertNoThrowWithValue(
            NIOSSLContext(
                configuration: config,
                callbackManager: nil
            ),
            file: file,
            line: line
        )
    }

    static func keyInFile(key: NIOSSLPrivateKey, passphrase: String) throws -> String {
        let fileName = try makeTemporaryFile(fileExtension: ".pem")
        let tempFile = open(fileName, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
        precondition(tempFile > 1, String(cString: strerror(errno)))
        let fileBio = CNIOBoringSSL_BIO_new_fp(fdopen(tempFile, "w+"), BIO_CLOSE)
        precondition(fileBio != nil)

        let manager = BoringSSLPassphraseCallbackManager { closure in closure(passphrase.utf8) }
        let rc = withExtendedLifetime(manager) { manager -> CInt in
            let userData = Unmanaged.passUnretained(manager).toOpaque()
            return key.withUnsafeMutableEVPPKEYPointer { ref in
                CNIOBoringSSL_PEM_write_bio_PrivateKey(
                    fileBio,
                    ref,
                    CNIOBoringSSL_EVP_aes_256_cbc(),
                    nil,
                    0,
                    globalBoringSSLPassphraseCallback,
                    userData
                )
            }
        }
        CNIOBoringSSL_BIO_free(fileBio)
        precondition(rc == 1)
        return fileName
    }

    func withTrustBundleInFile<T>(tempFile fileName: inout String?, fn: (String) throws -> T) throws -> T {
        fileName = try makeTemporaryFile()
        guard let fileName = fileName else {
            fatalError("couldn't make temp file")
        }
        let tempFile = fileName.withCString { ptr in
            open(ptr, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
        }
        precondition(tempFile > 1, String(cString: strerror(errno)))
        let fileBio = CNIOBoringSSL_BIO_new_fp(fdopen(tempFile, "w+"), BIO_CLOSE)
        precondition(fileBio != nil)

        let rc = NIOSSLIntegrationTest.cert.withUnsafeMutableX509Pointer { ref in
            CNIOBoringSSL_PEM_write_bio_X509(fileBio, ref)
        }
        CNIOBoringSSL_BIO_free(fileBio)
        precondition(rc == 1)
        return try fn(fileName)
    }

    func testSimpleEcho() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testHandshakeEventSequencing() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let readComplete: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let serverHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let serverChannel = try serverTLSChannel(
            context: context,
            handlers: [serverHandler, PromiseOnReadHandler(promise: readComplete)],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [SimpleEchoServer()],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()
        _ = try readComplete.futureResult.wait()

        // Ok, the channel is connected and we have written data to it. This means the TLS handshake is
        // done. Check the events.
        // TODO(cory): How do we wait until the read is done? Ideally we'd like to re-use the
        // PromiseOnReadHandler, but we need to get it into the pipeline first. Not sure how yet. Come back to me.
        // Maybe update serverTLSChannel to take an array of channel handlers?
        let expectedEvents: [EventRecorderHandler<TLSUserEvent>.RecordedEvents] = [
            .Registered,
            .Active,
            .UserEvent(TLSUserEvent.handshakeCompleted(negotiatedProtocol: nil)),
            .Read,
            .ReadComplete,
        ]

        XCTAssertEqual(expectedEvents, serverHandler.events)
    }

    func testShutdownEventSequencing() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let readComplete: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let serverHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let serverChannel = try serverTLSChannel(
            context: context,
            handlers: [serverHandler, PromiseOnReadHandler(promise: readComplete)],
            group: group
        )

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [SimpleEchoServer()],
            group: group,
            connectingTo: serverChannel.localAddress!
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        // Ok, we want to wait for the read to finish, then close the server and client connections.
        _ = try readComplete.futureResult.flatMap { (_: ByteBuffer) in
            serverChannel.close()
        }.flatMap {
            clientChannel.close()
        }.wait()

        let expectedEvents: [EventRecorderHandler<TLSUserEvent>.RecordedEvents] = [
            .Registered,
            .Active,
            .UserEvent(TLSUserEvent.handshakeCompleted(negotiatedProtocol: nil)),
            .Read,
            .ReadComplete,
            .UserEvent(TLSUserEvent.shutdownCompleted),
            .Inactive,
            .Unregistered,
        ]

        XCTAssertEqual(expectedEvents, serverHandler.events)
    }

    func testSubsequentWritesFailAfterCloseModeOutput() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try ServerBootstrap(group: group)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)  // Important!
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(
                        NIOSSLServerHandler(context: context),
                        SimpleEchoServer()
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [
                PromiseOnReadHandler(promise: completionPromise)
            ],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var buffer = clientChannel.allocator.buffer(capacity: 5)
        buffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(buffer).wait())

        XCTAssertNoThrow(try clientChannel.close(mode: .output).wait())
        XCTAssertThrowsError(try clientChannel.writeAndFlush(buffer).wait()) { error in
            XCTAssertEqual(.outputClosed, error as? ChannelError)
        }
    }

    func testCloseModeOutputServerAndClient() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let childChannelInitPromise: EventLoopPromise<Channel> = group.next().makePromise()

        let serverChannel: Channel = try ServerBootstrap(group: group)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)  // Important!
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(
                        NIOSSLServerHandler(context: context),
                        PromiseOnChildChannelInitHandler(promise: childChannelInitPromise),
                        SimpleEchoServer()
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannelInactivePromise: EventLoopPromise<Void> = group.next().makePromise()
        let shutdownPromise = group.next().makePromise(of: Void.self)
        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [
                PromiseOnReadHandler(promise: completionPromise),
                ShutdownVerificationHandler(
                    shutdownEvent: .input,
                    promise: shutdownPromise
                ),
                ChannelInactiveHandler(promise: clientChannelInactivePromise),
            ],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        XCTAssertNoThrow(try clientChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).wait())

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // Ok, the connection is definitely up.
        // Now retrieve the client channel that our server opened for the connection to our client.
        let connectionChildChannel = try childChannelInitPromise.futureResult.wait()

        // Closing the output of the connection on the server should automatically
        // close the input of the clientChannel.
        XCTAssertNoThrow(try connectionChildChannel.close(mode: .output).wait())
        try shutdownPromise.futureResult.wait()

        // Closing the output of the client channel (with input closed) should
        // result in full closure.
        XCTAssertNoThrow(try clientChannel.close(mode: .output).wait())
        XCTAssertNoThrow(try clientChannelInactivePromise.futureResult.wait())
    }

    func testCloseModeOutputTriggersFlush() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try ServerBootstrap(group: group)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)  // Important!
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(
                        NIOSSLServerHandler(context: context),
                        SimpleEchoServer()
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [
                PromiseOnReadHandler(promise: completionPromise)
            ],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let clientWriteFuture = clientChannel.write(originalBuffer)
        XCTAssertNoThrow(try clientChannel.close(mode: .output).wait())
        XCTAssertNoThrow(try clientWriteFuture.wait())

        let newBuffer = try assertNoThrowWithValue(completionPromise.futureResult.wait())
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testMultipleCloseOutput() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try ServerBootstrap(group: group)
            .childChannelOption(ChannelOptions.allowRemoteHalfClosure, value: true)  // Important!
            .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(
                        NIOSSLServerHandler(context: context),
                        SimpleEchoServer()
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // Ok, the connection is definitely up. Now we want to forcibly call close(mode: .output) on the channel several times with
        // different promises. None of these will fire until clean shutdown happens, but we want to confirm that *all* of them
        // fire.
        //
        // To avoid the risk of the I/O loop actually closing the connection before we're done, we need to hijack the
        // I/O loop and issue all the closes on that thread. Otherwise, the channel will probably pull off the TLS shutdown
        // before we get to the third call to close().
        let promises: [EventLoopPromise<Void>] = [
            group.next().makePromise(), group.next().makePromise(), group.next().makePromise(),
        ]
        group.next().execute {
            for promise in promises {
                clientChannel.close(mode: .output, promise: promise)
            }
        }

        XCTAssertNoThrow(try promises.first!.futureResult.wait())

        for promise in promises {
            // This should never block, but it may throw because the I/O is complete.
            // Suppress all errors, they're fine.
            _ = try? promise.futureResult.wait()
        }
    }

    func testMultipleClose() throws {
        var serverClosed = false
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel = try serverTLSChannel(context: context, handlers: [SimpleEchoServer()], group: group)
        defer {
            if !serverClosed {
                XCTAssertNoThrow(try serverChannel.close().wait())
            }
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // Ok, the connection is definitely up. Now we want to forcibly call close() on the channel several times with
        // different promises. None of these will fire until clean shutdown happens, but we want to confirm that *all* of them
        // fire.
        //
        // To avoid the risk of the I/O loop actually closing the connection before we're done, we need to hijack the
        // I/O loop and issue all the closes on that thread. Otherwise, the channel will probably pull off the TLS shutdown
        // before we get to the third call to close().
        let promises: [EventLoopPromise<Void>] = [
            group.next().makePromise(), group.next().makePromise(), group.next().makePromise(),
        ]
        group.next().execute {
            for promise in promises {
                serverChannel.close(promise: promise)
            }
        }

        XCTAssertNoThrow(try promises.first!.futureResult.wait())
        serverClosed = true

        for promise in promises {
            // This should never block, but it may throw because the I/O is complete.
            // Suppress all errors, they're fine.
            _ = try? promise.futureResult.wait()
        }
    }

    func testCoalescedWrites() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(context: context, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let writeCounter = WriteCountingHandler()
        let readPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [writeCounter],
            postHandlers: [PromiseOnReadHandler(promise: readPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // We're going to issue a number of small writes. Each of these should be coalesced together
        // such that the underlying layer sees only one write for them. The total number of
        // writes should be (after we flush) 3: one for Client Hello, one for Finished, and one
        // for the coalesced writes. However, we'll tolerate fewer!
        var originalBuffer = clientChannel.allocator.buffer(capacity: 1)
        originalBuffer.writeString("A")
        var writeFutures: [EventLoopFuture<()>] = []
        for _ in 0..<5 {
            writeFutures.append(clientChannel.write(originalBuffer))
        }

        clientChannel.flush()
        try EventLoopFuture<()>.andAllSucceed(writeFutures, on: clientChannel.eventLoop).wait()
        let writeCount = try readPromise.futureResult.map { (_: ByteBuffer) in
            // Here we're in the I/O loop, so we know that no further channel action will happen
            // while we dispatch this callback. This is the perfect time to check how many writes
            // happened.
            writeCounter.writeCount
        }.wait()
        XCTAssertLessThanOrEqual(writeCount, 3)
    }

    func testCoalescedWritesWithFutures() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(context: context, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // We're going to issue a number of small writes. Each of these should be coalesced together
        // and all their futures (along with the one for the flush) should fire, in order, with nothing
        // missed.
        let firedFutures: NIOLockedValueBox<[Int]> = .init([])
        let writeFutures: NIOLockedValueBox<[EventLoopFuture<()>]> = .init([])
        var originalBuffer = clientChannel.allocator.buffer(capacity: 1)
        originalBuffer.writeString("A")
        for index in 0..<5 {
            let promise: EventLoopPromise<Void> = group.next().makePromise()
            writeFutures.withLockedValue { $0.append(promise.futureResult) }
            promise.futureResult.map {
                XCTAssertEqual(firedFutures.withLockedValue { $0.count }, index)
                firedFutures.withLockedValue { $0.append(index) }
            }.whenFailure { error in
                XCTFail("Write promise failed: \(error)")
            }
            clientChannel.write(originalBuffer, promise: promise)
        }

        clientChannel.flush()
        try EventLoopFuture<()>.andAllSucceed(
            writeFutures.withLockedValue { $0 },
            on: clientChannel.eventLoop
        ).map {
            XCTAssertEqual(firedFutures.withLockedValue { $0 }, [0, 1, 2, 3, 4])
        }.recover { error in
            XCTFail("Write promised failed: \(error)")
        }.wait()
    }

    func testImmediateCloseSatisfiesPromises() throws {
        let context = try configuredSSLContext()
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(
            NIOSSLClientHandler(context: context, serverHostname: nil)
        )

        // Start by initiating the handshake.
        try channel.connect(to: SocketAddress(unixDomainSocketPath: "/tmp/doesntmatter")).wait()

        // Now call close. This should immediately close, satisfying the promise.
        let closePromise: EventLoopPromise<Void> = channel.eventLoop.makePromise()
        channel.close(promise: closePromise)

        XCTAssertNoThrow(try closePromise.futureResult.wait())
    }

    func testAddingTlsToActiveChannelStillHandshakes() throws {
        let context = try configuredSSLContext()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let recorderHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let channelActiveWaiter = ChannelActiveWaiter(promise: group.next().makePromise())
        let serverChannel = try serverTLSChannel(
            context: context,
            handlers: [recorderHandler, SimpleEchoServer(), channelActiveWaiter],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        // Create a client channel without TLS in it, and connect it.
        let readPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let clientChannel = try ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        PromiseOnReadHandler(promise: readPromise)
                    )
                }
            }
            .connect(to: serverChannel.localAddress!).wait()
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // Wait until the channel comes up, then confirm that no handshake has been
        // received. This hardly proves much, but it's enough.
        try channelActiveWaiter.waitForChannelActive()
        try group.next().submit {
            XCTAssertEqual(recorderHandler.events, [.Registered, .Active])
        }.wait()

        // Now, add the TLS handler to the pipeline.
        try clientChannel.eventLoop.submit {
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: context, serverHostname: nil),
                position: .first
            )
        }.wait()

        var data = clientChannel.allocator.buffer(capacity: 1)
        data.writeStaticString("x")
        try clientChannel.writeAndFlush(data).wait()

        // The echo should come back without error.
        _ = try readPromise.futureResult.wait()

        // At this point the handshake should be complete.
        try group.next().submit {
            XCTAssertEqual(
                recorderHandler.events[..<3],
                [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))]
            )
        }.wait()
    }

    func testValidatesHostnameOnConnectionFails() throws {
        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOSSLExtraError>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            preHandlers: [],
            postHandlers: [errorHandler],
            group: group,
            connectingTo: serverChannel.localAddress!
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOSSLExtraError]> = writeFuture.recover { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            ()
        }.map {
            errorHandler.errors
        }
        let actualErrors = try errorsFuture.wait()

        // This write will have failed, but that's fine: we just want it as a signal that
        // the handshake is done so we can make our assertions.
        let expectedErrors: [NIOSSLExtraError] = [NIOSSLExtraError.failedToValidateHostname]

        XCTAssertEqual(expectedErrors, actualErrors)
        XCTAssertEqual(
            actualErrors.first.map { String(describing: $0) },
            "NIOSSLExtraError.failedToValidateHostname: Couldn't find <none> in certificate from peer"
        )
    }

    func testValidatesHostnameOnConnectionSucceeds() throws {
        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let eventHandler = EventRecorderHandler<TLSUserEvent>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            preHandlers: [],
            postHandlers: [eventHandler],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        writeFuture.whenComplete { _ in
            XCTAssertEqual(
                eventHandler.events[..<3],
                [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))]
            )
        }
        try writeFuture.wait()
    }

    func testAdditionalValidationOnConnectionSucceeds() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let eventHandler = EventRecorderHandler<TLSUserEvent>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            additionalPeerCertificateVerificationCallback: { cert, channel in
                XCTAssertEqual(cert, Self.cert)
                return channel.eventLoop.makeSucceededFuture(())
            },
            preHandlers: [],
            postHandlers: [eventHandler],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        writeFuture.whenComplete { _ in
            XCTAssertEqual(
                eventHandler.events[..<3],
                [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))]
            )
        }
        try writeFuture.wait()
    }

    func testAdditionalValidationOnConnectionFails() throws {
        struct CustomUserError: Error {}
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<Error>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            additionalPeerCertificateVerificationCallback: { cert, channel in
                XCTAssertEqual(cert, Self.cert)
                return channel.eventLoop.makeFailedFuture(CustomUserError())
            },
            preHandlers: [],
            postHandlers: [errorHandler],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[Error]> = writeFuture.recover { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            ()
        }.map {
            errorHandler.errors
        }
        let actualErrors = try errorsFuture.wait()

        // This write will have failed, but that's fine: we just want it as a signal that
        // the handshake is done so we can make our assertions.
        XCTAssertEqual(actualErrors.count, 1)
        XCTAssertTrue(actualErrors.first is CustomUserError)
    }

    func testFlushWhileAdditionalValidationIsInProgressDoesNotActuallyFlush() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let additionalHandshakePromise = group.next().makePromise(of: Void.self)
        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let eventHandler = EventRecorderHandler<TLSUserEvent>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            additionalPeerCertificateVerificationCallback: { cert, channel in
                XCTAssertEqual(cert, Self.cert)
                channel.flush()
                return additionalHandshakePromise.futureResult
            },
            preHandlers: [],
            postHandlers: [eventHandler],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        let writeFuture = clientChannel.writeAndFlush(ByteBuffer(string: "Hello"))
        XCTAssertThrowsError(try writeFuture.timeout(after: .milliseconds(100)).wait())
        additionalHandshakePromise.succeed(())
        writeFuture.whenComplete { _ in
            XCTAssertEqual(
                eventHandler.events[..<3],
                [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))]
            )
        }
        try writeFuture.wait()
    }

    func testDontLoseClosePromises() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        var channelClosed = false
        defer {
            // We know this will throw.
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        let context = try configuredSSLContext()

        try serverChannel.pipeline.syncOperations.addHandler(
            NIOSSLServerHandler(context: context)
        )
        try clientChannel.pipeline.syncOperations.addHandler(
            try NIOSSLClientHandler(context: context, serverHostname: nil)
        )

        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // Ok, we're connected. Good stuff! Now, we want to hit this specific window:
        // 1. Call close() on the server channel. This will transition it to the closing state.
        // 2. Fire channelInactive on the serverChannel. This should cause it to drop all state and
        //    fire the close promise.
        // Because we're using the embedded channel here, we don't need to worry about thread
        // synchronization: all of this should succeed synchronously. If it doesn't, that's
        // a bug too!
        let closePromise = serverChannel.close()
        closePromise.assumeIsolated().whenComplete { _ in
            // This looks like unsynchronized access to channelClosed, but it isn't: as we're
            // using EmbeddedChannel here there is no cross-thread hopping.
            channelClosed = true
        }
        XCTAssertFalse(channelClosed)

        serverChannel.pipeline.fireChannelInactive()
        XCTAssertTrue(channelClosed)

        closePromise.map {
            XCTFail("Unexpected success")
        }.whenFailure { error in
            switch error {
            case let e as NIOSSLError where e == .uncleanShutdown:
                break
            default:
                XCTFail("Unexpected error: \(error)")
            }
        }

        // Now clean up the client channel. We need to also fire the channel inactive here as there is
        // no-one left for the client channel to end the connection with.
        _ = clientChannel.close()
        clientChannel.pipeline.fireChannelInactive()
    }

    func testTrustStoreOnDisk() throws {
        var tempFile: String? = nil
        let serverCtx = try configuredSSLContext()
        let config: TLSConfiguration = try withTrustBundleInFile(tempFile: &tempFile) {
            var config = TLSConfiguration.makeClientConfiguration()
            config.certificateVerification = .noHostnameVerification
            config.trustRoots = .file($0)
            config.certificateChain = [.certificate(NIOSSLIntegrationTest.cert)]
            config.privateKey = .privateKey(NIOSSLIntegrationTest.key)
            return config
        }
        defer {
            precondition(
                .some(0) == tempFile.map { unlink($0) },
                "couldn't remove temp file \(tempFile.debugDescription)"
            )
        }
        let clientCtx = try assertNoThrowWithValue(NIOSSLContext(configuration: config))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        let serverChannel: Channel = try serverTLSChannel(
            context: serverCtx,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            _ = try? clientChannel.close().wait()
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")

        try clientChannel.writeAndFlush(originalBuffer).wait()
        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testChecksTrustStoreOnDisk() throws {
        let serverCtx = try configuredSSLContext()
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .file(FileManager.default.temporaryDirectory.path)
        clientConfig.certificateChain = [.certificate(NIOSSLIntegrationTest.cert)]
        clientConfig.privateKey = .privateKey(NIOSSLIntegrationTest.key)
        let clientCtx = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(
            context: serverCtx,
            handlers: [],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOSSLError>()
        let clientChannel = try clientTLSChannel(
            context: clientCtx,
            preHandlers: [],
            postHandlers: [errorHandler],
            group: group,
            connectingTo: serverChannel.localAddress!
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOSSLError]> = writeFuture.recover { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            ()
        }.map {
            errorHandler.errors
        }
        let actualErrors = try errorsFuture.wait()

        // The actual error is non-deterministic depending on platform and version, so we don't
        // really try to make too many assertions here.
        XCTAssertEqual(actualErrors.count, 1)
        try clientChannel.closeFuture.wait()
    }

    func testReadAfterCloseNotifyDoesntKillProcess() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        let context = try configuredSSLContext()

        try serverChannel.pipeline.syncOperations.addHandler(
            NIOSSLServerHandler(context: context)
        )
        try clientChannel.pipeline.syncOperations.addHandler(
            try NIOSSLClientHandler(context: context, serverHostname: nil)
        )

        let addr = try SocketAddress(unixDomainSocketPath: "/tmp/whatever2")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // Ok, we're connected. Now we want to close the server, and have that trigger a client CLOSE_NOTIFY.
        // However, when we deliver that CLOSE_NOTIFY we're then going to immediately send another chunk of
        // data. We can get away with doing this because the Embedded channel fires any promise for close()
        // before it fires channelInactive, which will allow us to fire channelRead from within the callback.
        let closePromise = serverChannel.close()
        closePromise.whenComplete { _ in
            var buffer = serverChannel.allocator.buffer(capacity: 5)
            buffer.writeStaticString("hello")
            serverChannel.pipeline.fireChannelRead(buffer)
            serverChannel.pipeline.fireChannelReadComplete()
        }

        XCTAssertNoThrow(try serverChannel.throwIfErrorCaught())

        XCTAssertThrowsError(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)) {
            error in
            XCTAssertEqual(.readInInvalidTLSState, error as? NIOSSLError)
        }
    }

    func testUnprocessedDataOnReadPathBeforeClosing() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        let context = try configuredSSLContext()

        let completePromise: EventLoopPromise<ByteBuffer> = serverChannel.eventLoop.makePromise()

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                ReadRecordingHandler(completePromise: completePromise)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(context: context, serverHostname: nil)
            )
        )

        let addr = try SocketAddress(unixDomainSocketPath: "/tmp/whatever2")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // Ok, we're connected. Now we want to close the server, and have that trigger a client CLOSE_NOTIFY.
        // After the CLOSE_NOTIFY create another chunk of data.
        let serverClosePromise = serverChannel.close()

        // Create a new chunk of data after the close.
        var clientBuffer = clientChannel.allocator.buffer(capacity: 5)
        clientBuffer.writeStaticString("hello")
        _ = try clientChannel.writeAndFlush(clientBuffer).wait()
        let clientClosePromise = clientChannel.close()

        // Use interactInMemory to finish the reads and writes.
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try clientClosePromise.wait())
        XCTAssertNoThrow(try serverClosePromise.wait())

        // Now check what we read.
        var readData = try assertNoThrowWithValue(completePromise.futureResult.wait())
        XCTAssertEqual(readData.readString(length: readData.readableBytes)!, "hello")
    }

    func testZeroLengthWrite() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel = try serverTLSChannel(
            context: context,
            handlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group
        )
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            _ = try? clientChannel.close().wait()
        }

        // Write several zero-length buffers *and* one with some actual data. Only one should
        // be written.
        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        let promises = (0...5).map { (_: Int) in clientChannel.write(originalBuffer) }
        originalBuffer.writeStaticString("hello")
        _ = try clientChannel.writeAndFlush(originalBuffer).wait()

        // At this time all the writes should have succeeded.
        for promise in promises {
            XCTAssertNoThrow(try promise.wait())
        }

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testZeroLengthWritePromisesFireInOrder() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        let context = try configuredSSLContext()

        try serverChannel.pipeline.syncOperations.addHandler(
            NIOSSLServerHandler(context: context)
        )
        try clientChannel.pipeline.syncOperations.addHandler(
            try NIOSSLClientHandler(context: context, serverHostname: nil)
        )

        let addr = try SocketAddress(unixDomainSocketPath: "/tmp/whatever2")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // This test fires three writes, flushing between them all. We want to confirm that all of the
        // writes are succeeded in order. To do that, we want to add a WriteDelayHandler to
        // prevent the EmbeddedChannel succeeding the early writes.
        let writeDelayer = WriteDelayHandler()
        try clientChannel.pipeline.syncOperations.addHandler(writeDelayer, position: .first)
        var writeCount = 0
        let emptyBuffer = clientChannel.allocator.buffer(capacity: 16)
        var buffer = clientChannel.allocator.buffer(capacity: 16)
        buffer.writeStaticString("hello world")

        clientChannel.write(buffer).assumeIsolated().whenComplete { _ in
            XCTAssertEqual(writeCount, 0)
            writeCount = 1
        }
        clientChannel.flush()
        clientChannel.write(emptyBuffer).assumeIsolated().whenComplete { _ in
            XCTAssertEqual(writeCount, 1)
            writeCount = 2
        }
        clientChannel.flush()
        clientChannel.write(buffer).assumeIsolated().whenComplete { _ in
            XCTAssertEqual(writeCount, 2)
            writeCount = 3
        }
        clientChannel.flush()

        XCTAssertEqual(writeCount, 0)
        writeDelayer.forceFlush()
        XCTAssertEqual(writeCount, 3)

        serverChannel.pipeline.fireChannelInactive()
        clientChannel.pipeline.fireChannelInactive()
    }

    func testEncryptedFileInContext() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testFlushPendingReadsOnCloseNotify() throws {
        let context = try assertNoThrowWithValue(configuredSSLContext())
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        let completePromise: EventLoopPromise<ByteBuffer> = serverChannel.eventLoop.makePromise()

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                ReadRecordingHandler(completePromise: completePromise)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(context: context, serverHostname: nil)
            )
        )

        // Connect
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try connectFuture.wait())

        // Here we want to issue a write, a flush, and then a close. This will trigger a CLOSE_NOTIFY message to be emitted by the
        // client. Unfortunately, interactInMemory doesn't do quite what we want, as we need to coalesce all these writes, so
        // we'll have to do some of this ourselves.
        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        clientChannel.writeAndFlush(originalBuffer, promise: nil)
        let clientClosePromise = clientChannel.close()

        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        while case .some(.byteBuffer(var data)) = try clientChannel.readOutbound(as: IOData.self) {
            buffer.writeBuffer(&data)
        }
        XCTAssertNoThrow(try serverChannel.writeInbound(buffer))

        // Now we can interact. The server should close.
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try clientClosePromise.wait())

        // Now check what we read.
        var readData = try assertNoThrowWithValue(completePromise.futureResult.wait())
        XCTAssertEqual(readData.readString(length: readData.readableBytes)!, "Hello")
    }

    @available(*, deprecated, message: "Testing deprecated API surface")
    func testForcingVerificationFailure() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: context, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOSSLError>()
        let clientChannel = try clientTLSChannel(
            context: try configuredClientContext(),
            preHandlers: [],
            postHandlers: [errorHandler],
            group: group,
            connectingTo: serverChannel.localAddress!,
            verificationCallback: { preverify, certificate in
                XCTAssertEqual(preverify, .certificateVerified)
                return .failed
            }
        )

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOSSLError]> = writeFuture.recover { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            ()
        }.map {
            errorHandler.errors
        }
        let actualErrors = try errorsFuture.wait()

        // This write will have failed, but that's fine: we just want it as a signal that
        // the handshake is done so we can make our assertions.
        XCTAssertEqual(actualErrors.count, 1)
        switch actualErrors.first! {
        case .handshakeFailed:
            // expected
            break
        case let error:
            XCTFail("Unexpected error: \(error)")
        }
    }

    @available(*, deprecated, message: "Testing deprecated API surface")
    func testExtractingCertificates() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let certificates = NIOLockedValueBox([NIOSSLCertificate]())
        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            verificationCallback: { verify, certificate in
                certificates.withLockedValue { $0.append(certificate) }
                return verify
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        XCTAssertEqual(certificates.withLockedValue { $0.count }, 1)
    }

    func testForcingVerificationFailureNewCallback() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: context, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)
        let clientChannel = try clientTLSChannel(
            context: try configuredClientContext(),
            preHandlers: [],
            postHandlers: [handshakeWatcher],
            group: group,
            connectingTo: serverChannel.localAddress!,
            customVerificationCallback: .callback { _, promise in
                promise.succeed(.failed)
            }
        )

        defer {
            // Ignore errors here, the channel should be closed already by the time this happens.
            try? clientChannel.close().wait()
        }

        XCTAssertThrowsError(try handshakeResultPromise.futureResult.wait())
    }

    func testErroringNewVerificationCallback() throws {
        enum LocalError: Error {
            case kaboom
        }

        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: context, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)
        let clientChannel = try clientTLSChannel(
            context: try configuredClientContext(),
            preHandlers: [],
            postHandlers: [handshakeWatcher],
            group: group,
            connectingTo: serverChannel.localAddress!,
            customVerificationCallback: .callback { _, promise in
                promise.fail(LocalError.kaboom)
            }
        )
        defer {
            // Ignore errors here, the channel should be closed already by the time this happens.
            try? clientChannel.close().wait()
        }

        XCTAssertThrowsError(try handshakeResultPromise.futureResult.wait())
    }

    func testReadsAreUnbufferedAfterHandshake() throws {
        // This is a regression test for rdar://96850712
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        config.certificateVerification = .noHostnameVerification
        let context = try assertNoThrowWithValue(NIOSSLContext(configuration: config))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromiseFired = NIOLockedValueBox(false)

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        completionPromise.futureResult.whenComplete { _ in
            completionPromiseFired.withLockedValue {
                $0 = true
            }
        }

        let handshakeCompletePromise: NIOLockedValueBox<EventLoopPromise<NIOSSLVerificationResult>?> = .init(nil)
        let handshakeFiredPromise: EventLoopPromise<Void> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            customVerificationCallback: { innerCertificates, promise in
                handshakeCompletePromise.withLockedValue { $0 = promise }
                handshakeFiredPromise.succeed(())
            }
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: try configuredSSLContext(),
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        clientChannel.writeAndFlush(originalBuffer, promise: nil)

        // This has driven the handshake to begin, so we can wait for that.
        XCTAssertNoThrow(try handshakeFiredPromise.futureResult.wait())

        // We can now check whether the completion promise has fired: it should not have.
        completionPromiseFired.withLockedValue {
            XCTAssertFalse($0)
        }

        // Ok, allow the handshake to run.
        handshakeCompletePromise.withLockedValue { $0!.succeed(.certificateVerified) }

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testNewCallbackCanDelayHandshake() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromiseFired = NIOLockedValueBox(false)

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()
        completionPromise.futureResult.whenComplete { _ in
            completionPromiseFired.withLockedValue {
                $0 = true
            }
        }

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let handshakeCompletePromise: NIOLockedValueBox<EventLoopPromise<NIOSSLVerificationResult>?> = .init(nil)
        let handshakeFiredPromise: EventLoopPromise<Void> = group.next().makePromise()

        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: .callback { innerCertificates, promise in
                handshakeCompletePromise.withLockedValue { $0 = promise }
                handshakeFiredPromise.succeed(())
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        clientChannel.writeAndFlush(originalBuffer, promise: nil)

        // This has driven the handshake to begin, so we can wait for that.
        XCTAssertNoThrow(try handshakeFiredPromise.futureResult.wait())

        // We can now check whether the completion promise has fired: it should not have.
        completionPromiseFired.withLockedValue {
            XCTAssertFalse($0)
        }

        // Ok, allow the handshake to run.
        handshakeCompletePromise.withLockedValue { $0!.succeed(.certificateVerified) }

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testExtractingCertificatesNewCallback() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let certificates = NIOLockedValueBox([NIOSSLCertificate]())
        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: .callback { innerCertificates, promise in
                certificates.withLockedValue { $0 = innerCertificates }
                promise.succeed(.certificateVerified)
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        XCTAssertEqual(certificates.withLockedValue { $0 }, [NIOSSLIntegrationTest.cert])
    }

    func testCustomVerificationCallbackExtractingCertificateChain() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: .callbackWithMetadata { innerCertificates, promise in
                // Return `innerCertificates` as the validated certificate chain
                promise.succeed(
                    .certificateVerified(
                        VerificationMetadata(ValidatedCertificateChain(innerCertificates))
                    )
                )
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // We should be able to extract the certificate chain from the channel
        let extractedCertChain = try clientChannel.nioSSL_peerValidatedCertificateChain().wait()
        XCTAssertEqual(extractedCertChain?.validatedChain, [NIOSSLIntegrationTest.cert])
    }

    func testCustomVerificationCallbackNotReturningChain() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: .callbackWithMetadata { innerCertificates, promise in
                // Initialize an empty VerificationMetadata without a chain.
                promise.succeed(.certificateVerified(VerificationMetadata(nil)))
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // We should not be able to extract the chain: no chain was returned
        XCTAssertNil(try clientChannel.nioSSL_peerValidatedCertificateChain().wait())
    }

    func testCustomVerificationCallbackDelayReturningCertificateChain() throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let clientChannel = try clientTLSChannel(
            context: configuredClientContext(),
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: CustomCallback.callbackWithMetadata { innerCertificates, promise in
                // Complete the promise in 10 milliseconds
                promise.futureResult.eventLoop.scheduleTask(in: .milliseconds(10)) {
                    promise.succeed(
                        .certificateVerified(
                            VerificationMetadata(ValidatedCertificateChain(innerCertificates))
                        )
                    )
                }
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        // We should be able to extract the certificate chain.
        let extractedCertChain = try clientChannel.nioSSL_peerValidatedCertificateChain().wait()
        XCTAssertEqual(extractedCertChain?.validatedChain, [NIOSSLIntegrationTest.cert])
    }

    func testNewCallbackCombinedWithDefaultTrustStore() throws {
        // This test is mostly useful on macOS, where it previously failed due to an excessive assertion.
        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .fullVerification
        clientConfig.trustRoots = .default
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: serverContext, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let handshakeCompletePromise = group.next().makePromise(of: Void.self)
        let customCallbackCalledPromise = group.next().makePromise(of: Void.self)
        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [WaitForHandshakeHandler(handshakeResultPromise: handshakeCompletePromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost",
            customVerificationCallback: .callback { _, promise in
                // Note that we override certificate verification here.
                customCallbackCalledPromise.succeed(())
                promise.succeed(.certificateVerified)
            }
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        XCTAssertNoThrow(try customCallbackCalledPromise.futureResult.wait())
        XCTAssertNoThrow(try handshakeCompletePromise.futureResult.wait())
    }

    func testMacOSVerificationCallbackIsNotUsedIfVerificationDisabled() throws {
        // This test is mostly useful on macOS, where it validates that disabling verification actually, well,
        // disables verification.
        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .none
        clientConfig.trustRoots = .default
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: serverContext, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let handshakeCompletePromise = group.next().makePromise(of: Void.self)
        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [WaitForHandshakeHandler(handshakeResultPromise: handshakeCompletePromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // This connection should succeed, as certificate verification is disabled.
        XCTAssertNoThrow(try handshakeCompletePromise.futureResult.wait())
    }

    func testMacOSConnectionFailsIfServerVerificationOptionalAndPeerPresentsUntrustedCert() throws {
        // This test checks that when setting verification to `.optionalVerification`, a peer cannot successfully
        // connect when they present an untrusted certificate. On macOS, this exercises the SecTrust validation backend,
        // as `serverConfig.trustRoots` is set to `.default` (see the behavioral matrix in
        // `NIOSSL/Docs/trust-roots-behavior.md`).
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([NIOSSLIntegrationTest.cert])]
        // The client presents a random cert but the server won't trust it
        let clientCertAndPrivateKey = generateSelfSignedCert()
        clientConfig.certificateChain = [.certificate(clientCertAndPrivateKey.0)]
        clientConfig.privateKey = .privateKey(clientCertAndPrivateKey.1)

        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let handshakeCompletePromise = group.next().makePromise(of: Void.self)
        let serverChannel: Channel = try serverTLSChannel(
            context: serverContext,
            handlers: [WaitForHandshakeHandler(handshakeResultPromise: handshakeCompletePromise)],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // The handshake should fail: certificate verification is optional and the client hasn't presented any certs.
        XCTAssertThrowsError(try handshakeCompletePromise.futureResult.wait())
    }

    func testMacOSConnectionSuccessfulIfServerVerificationOptionalAndPeerPresentsTrustedCert() throws {
        // This test checks that when setting verification to `.optionalVerification`, a peer can successfully
        // connect when they present a trusted certificate. On macOS, this exercises the SecTrust validation backend,
        // as `serverConfig.trustRoots` is set to `.default` and the client cert is registered under
        // `additionalTrustRoots` (see the behavioral matrix in `NIOSSL/Docs.docc/trust-roots-behavior.md`).
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([NIOSSLIntegrationTest.cert])]
        // The client presents a generated cert
        let clientCertAndPrivateKey = generateSelfSignedCert()
        clientConfig.certificateChain = [.certificate(clientCertAndPrivateKey.0)]
        clientConfig.privateKey = .privateKey(clientCertAndPrivateKey.1)

        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default
        // The server trusts the client's generated cert
        serverConfig.additionalTrustRoots = [.certificates([clientCertAndPrivateKey.0])]

        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let handshakeCompletePromise = group.next().makePromise(of: Void.self)
        let serverChannel: Channel = try serverTLSChannel(
            context: serverContext,
            handlers: [WaitForHandshakeHandler(handshakeResultPromise: handshakeCompletePromise)],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // The handshake should succeed: verification is optional, and the client presents a cert the server trusts.
        XCTAssertNoThrow(try handshakeCompletePromise.futureResult.wait())
    }

    func testMacOSConnectionSuccessfulIfServerVerificationOptionalAndNoPeerCert() throws {
        // This test checks that when setting verification to `.optionalVerification`, a peer can successfully connect
        // when they don't present any certificate. On macOS, this exercises the SecTrust validation backend, as
        // `serverConfig.trustRoots` is set to `.default` (see the behavioral matrix in
        // `NIOSSL/Docs.docc/trust-roots-behavior.md`).
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        serverConfig.certificateVerification = .optionalVerification
        serverConfig.trustRoots = .default

        // The client doesn't present any certs
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .default
        clientConfig.additionalTrustRoots = [.certificates([NIOSSLIntegrationTest.cert])]

        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let handshakeCompletePromise = group.next().makePromise(of: Void.self)
        let serverChannel: Channel = try serverTLSChannel(
            context: serverContext,
            handlers: [WaitForHandshakeHandler(handshakeResultPromise: handshakeCompletePromise)],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // The handshake should succeed: certificate verification is optional and the client hasn't presented any certs.
        XCTAssertNoThrow(try handshakeCompletePromise.futureResult.wait())
    }

    func testServerHasNewCallbackCalledToo() throws {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        config.certificateVerification = .fullVerification
        config.trustRoots = .default
        let context = try assertNoThrowWithValue(NIOSSLContext(configuration: config))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let handshakeResultPromise = group.next().makePromise(of: Void.self)
        let handshakeWatcher = WaitForHandshakeHandler(handshakeResultPromise: handshakeResultPromise)
        let serverChannel: Channel = try serverTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [handshakeWatcher],
            group: group,
            customVerificationCallback: { _, promise in
                promise.succeed(.failed)
            }
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: try configuredSSLContext(),
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!
        )

        defer {
            // Ignore errors here, the channel should be closed already by the time this happens.
            try? clientChannel.close().wait()
        }

        XCTAssertThrowsError(try handshakeResultPromise.futureResult.wait())
    }

    func testRepeatedClosure() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect both cases to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: context, serverHostname: nil)
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // We're going to close twice: the first one without a promise, the second one with one.
        let closed = NIOLockedValueBox(false)
        clientChannel.close(promise: nil)
        clientChannel.close().whenComplete { _ in
            closed.withLockedValue { $0 = true }
        }
        XCTAssertFalse(closed.withLockedValue { $0 })
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        // The closure should have happened.
        XCTAssertTrue(closed.withLockedValue { $0 })
    }

    func testClosureTimeout() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect both cases to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: context, serverHostname: nil)
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        let closed = NIOLockedValueBox(false)
        clientChannel.close().whenComplete { _ in
            closed.withLockedValue { $0 = true }
        }

        clientChannel.close().whenFailure { error in
            XCTAssertTrue(error is NIOSSLCloseTimedOutError)
        }

        // Send CLOSE_NOTIFY from the client.
        while let clientDatum = try clientChannel.readOutbound(as: IOData.self) {
            try serverChannel.writeInbound(clientDatum)
        }

        XCTAssertFalse(closed.withLockedValue { $0 })

        // Let the shutdown timeout.
        clientChannel.embeddedEventLoop.advanceTime(by: context.configuration.shutdownTimeout)
        XCTAssertTrue(closed.withLockedValue { $0 })

        // Let the server shutdown.
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
    }

    func testReceivingGibberishAfterAttemptingToClose() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        let clientClosed = NIOLockedValueBox(false)

        defer {
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                clientHandler
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                handshakeHandler
            )
        )

        // Mark the closure of the client.
        clientChannel.closeFuture.whenComplete { _ in
            clientClosed.withLockedValue { $0 = true }
        }

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's close the client connection.
        clientChannel.close(promise: nil)
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertFalse(clientClosed.withLockedValue { $0 })

        // Now we're going to simulate the client receiving gibberish data in response, instead
        // of a CLOSE_NOTIFY.
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeStaticString("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")

        XCTAssertThrowsError(try clientChannel.writeInbound(buffer)) { error in
            let errorString = String(describing: error)

            let range = NSRange(location: 0, length: errorString.utf16.count)
            let regex = try! NSRegularExpression(
                pattern:
                    "sslError\\(\\[Error\\: 268435703 error\\:100000f7\\:SSL routines\\:OPENSSL_internal\\:WRONG_VERSION_NUMBER at .*\\/[A-Za-z_]+\\.cc\\:[0-9]+\\]\\)"
            )
            XCTAssertNotNil(regex.firstMatch(in: errorString, options: [], range: range))
        }
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertTrue(clientClosed.withLockedValue { $0 })

        // Clean up by bringing the server up to speed
        serverChannel.pipeline.fireChannelInactive()
    }

    func testPendingWritesFailWhenFlushedOnClose() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: context)
            )
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                clientHandler
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Queue up a write.
        let writeCompleted = NIOLockedValueBox(false)
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeStaticString("Hello, world!")
        clientChannel.write(buffer).map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
            writeCompleted.withLockedValue { $0 = true }
        }

        // We haven't spun the event loop, so the handlers are still in the pipeline. Now attempt to close.
        let closed = NIOLockedValueBox(false)
        clientChannel.closeFuture.whenComplete { _ in
            closed.withLockedValue { $0 = true }
        }

        XCTAssertFalse(writeCompleted.withLockedValue { $0 })
        clientChannel.close(promise: nil)
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertFalse(writeCompleted.withLockedValue { $0 })
        XCTAssertFalse(closed.withLockedValue { $0 })

        // Now try to flush the write. This should fail the write early, and take out the connection.
        clientChannel.flush()
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertTrue(writeCompleted.withLockedValue { $0 })
        XCTAssertTrue(closed.withLockedValue { $0 })

        // Bring the server up to speed.
        serverChannel.pipeline.fireChannelInactive()
    }

    func testChannelInactiveAfterCloseNotify() throws {
        class SecondChannelInactiveSwallower: ChannelInboundHandler {
            typealias InboundIn = Any
            private var channelInactiveCalls = 0

            func channelInactive(context: ChannelHandlerContext) {
                if self.channelInactiveCalls == 0 {
                    self.channelInactiveCalls += 1
                    context.fireChannelInactive()
                }
            }
        }

        class FlushOnReadHandler: ChannelInboundHandler {
            typealias InboundIn = Any

            func channelRead(context: ChannelHandlerContext, data: NIOAny) {
                context.pipeline.fireChannelInactive()
            }
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            _ = try? serverChannel.finish()
            // The client channel is closed in the test.
        }

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandlers(
                SecondChannelInactiveSwallower(),
                NIOSSLServerHandler(context: context),
                FlushOnReadHandler()
            )
        )

        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(context: context, serverHostname: nil)
            )
        )

        // Connect
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        XCTAssertNoThrow(try serverChannel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 5678)).wait())
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try connectFuture.wait())

        // Here we want to issue a write, a flush, and then a close. This will trigger a CLOSE_NOTIFY message to be emitted by the
        // client. Unfortunately, interactInMemory doesn't do quite what we want, as we need to coalesce all these writes, so
        // we'll have to do some of this ourselves.
        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        let clientClose = clientChannel.writeAndFlush(originalBuffer)
        clientChannel.close(promise: nil)

        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        while case .some(.byteBuffer(var data)) = try clientChannel.readOutbound(as: IOData.self) {
            buffer.writeBuffer(&data)
        }

        // The client has sent CLOSE_NOTIFY, so the server will unbuffer any reads it has. This in turn
        // causes channelInactive to be fired back into the SSL handler.
        XCTAssertThrowsError(try serverChannel.writeInbound(buffer)) { error in
            XCTAssertEqual(NIOSSLError.uncleanShutdown, error as? NIOSSLError)
        }

        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try clientClose.wait())
    }

    func testKeyLoggingClientAndServer() throws {
        let clientLines: UnsafeMutableTransferBox<[ByteBuffer]> = .init([])
        let serverLines: UnsafeMutableTransferBox<[ByteBuffer]> = .init([])

        let clientContext = try assertNoThrowWithValue(
            self.configuredSSLContext(keyLogCallback: { clientLines.wrappedValue.append($0) })
        )
        let serverContext = try assertNoThrowWithValue(
            self.configuredSSLContext(keyLogCallback: { serverLines.wrappedValue.append($0) })
        )

        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            // These error as the channel is already closed.
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        // Handshake
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(
                NIOSSLClientHandler(context: clientContext, serverHostname: nil)
            )
        )
        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: serverContext)
            )
        )
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.addHandler(handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // In our code this should do TLS 1.3, so we expect 5 lines each.
        XCTAssertEqual(clientLines.wrappedValue.count, 5)
        XCTAssertEqual(serverLines.wrappedValue.count, 5)

        // Each in the same order.
        XCTAssertEqual(clientLines.wrappedValue, serverLines.wrappedValue)

        // Each line should be newline terminated.
        for line in clientLines.wrappedValue {
            XCTAssertTrue(line.readableBytesView.last! == UInt8(ascii: "\n"))
        }
        for line in serverLines.wrappedValue {
            XCTAssertTrue(line.readableBytesView.last! == UInt8(ascii: "\n"))
        }

        // Close and let the two channels shutdown.
        clientChannel.close(promise: nil)
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
    }

    func testLoadsOfCloses() throws {
        let context = try configuredSSLContext()

        // 3 threads so server, client, and accepted all have their own thread.
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 3)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: context, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!
        )
        let closeFutures = (0..<20).map { _ in
            clientChannel.close()
        }
        XCTAssertNoThrow(try EventLoopFuture<Void>.andAllComplete(closeFutures, on: clientChannel.eventLoop).wait())
    }

    func testWriteFromFailureOfWrite() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            // Both were closed uncleanly in the test, so they'll throw.
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try configuredSSLContext()

        try serverChannel.pipeline.syncOperations.addHandler(
            NIOSSLServerHandler(context: context)
        )
        try clientChannel.pipeline.syncOperations.addHandler(
            try NIOSSLClientHandler(context: context, serverHostname: nil)
        )

        // Do the handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // Ok, we're gonna do a weird thing here. We're going to queue up a write, whose write promise is going
        // to issue another write. In older builds, this would crash due to an exclusivity violation.
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeBytes("Hello, world!".utf8)

        clientChannel.write(buffer).whenComplete { [buffer] _ in
            clientChannel.writeAndFlush(buffer, promise: nil)
        }

        // Now we're going to fire channel inactive on the client. This used to crash: now it doesn't.
        clientChannel.pipeline.fireChannelInactive()

        // Do the same for the server, but we don't care about the outcome.
        serverChannel.pipeline.fireChannelInactive()
    }

    func testChannelInactiveDuringHandshakeSucceeded() throws {
        // This test aims to reproduce a very unusual crash. I've never been able to come up with a clear justification of
        // how we managed to hit it, but it goes a bit like this:
        //
        // 1. During a TLS handshake, a server performs a `channelRead` that triggers a handshakeCompleted message.
        // 2. Synchronously, during that pipeline traversal, we end up with a read buffer that also contains a CLOSE_NOTIFY alert.
        //     This may have arrived in the same packet with the handshake completion message, or as a result of something we did.
        // 3. Additionally, we manage to synchronously enter the .closed or .unwrapped state. This is hard to imagine, but it can
        //     happen in a few ways: channelInactive forces this transition, and managing to do a shutdown reentrantly due to extra
        //     I/O can trigger it as well.
        // 4. We then progress through the handshake and crash.
        //
        // To make this manifest in the test we use a pair of promises and finagle the I/O such that everything goes wrong at once.
        // This can indicate how unusual the circumstance is in which this happens. Nonetheless, we've seen it happen on production
        // systems.
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            // Both were closed uncleanly in the test, but the server error was already
            // consumed.
            XCTAssertNoThrow(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try configuredSSLContext()
        let clientChannelCompletedPromise = clientChannel.eventLoop.makePromise(of: Void.self)
        let clientChannelCompletedHandler = WaitForHandshakeHandler(
            handshakeResultPromise: clientChannelCompletedPromise
        )
        let serverChannelCompletedPromise = serverChannel.eventLoop.makePromise(of: Void.self)
        let serverChannelCompletedHandler = WaitForHandshakeHandler(
            handshakeResultPromise: serverChannelCompletedPromise
        )

        clientChannelCompletedPromise.futureResult.whenSuccess {
            // Here we need to immediately (and _recursively_) ask the client channel to shutdown. This should force a CLOSE_NOTIFY
            // message out in the same tick as the handshake message.
            clientChannel.close(promise: nil)

            // Now deliver all the client messages to the server channel _in one go_.
            var flattenedBytes = clientChannel.allocator.buffer(capacity: 1024)
            while let clientDatum = try! clientChannel.readOutbound(as: ByteBuffer.self) {
                flattenedBytes.writeImmutableBuffer(clientDatum)
            }

            // Can't use XCTAssertThrowsError here, this function call isn't allowed to throw.
            do {
                try serverChannel.writeInbound(flattenedBytes)
                XCTFail("Expected to throw")
            } catch {
                guard case .some(.uncleanShutdown) = error as? NIOSSLError else {
                    XCTFail("Unexpected error \(error)")
                    return
                }
            }
        }

        serverChannelCompletedPromise.futureResult.whenSuccess {
            // Here we do something very, very dangerous: we call fireChannelInactive on our own channel.
            // This simulates us hitting a close condition in some other form.
            serverChannel.pipeline.fireChannelInactive()
        }

        XCTAssertNoThrow(
            try serverChannel.pipeline.syncOperations.addHandlers([
                NIOSSLServerHandler(context: context), serverChannelCompletedHandler,
            ])
        )
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandlers([
                try NIOSSLClientHandler(context: context, serverHostname: nil), clientChannelCompletedHandler,
            ])
        )

        // Do the handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // We now need to forcibly shutdown the client channel, as otherwise it'll wedge waiting for a server that never comes back.
        clientChannel.pipeline.fireChannelInactive()
    }

    func testTrustedFirst() throws {
        // We need to explain this test a bit.
        //
        // BoringSSL has a flag: X509_V_FLAG_TRUSTED_FIRST. This flag affects the way the X509 verifier works. In particular,
        // it causes the verifier to look for certificates in the trust store _before_ it looks for them in the chain. This
        // is important, because some misbehaving clients may send an excessively long chain that, in some cases, includes
        // certificates we don't trust!
        //
        // In this case, the server has a cert that was signed by a CA whose original certificate has expired. We, the client,
        // have a valid root certificate for the intermediate that _actually_ issued the key, which is now a root, as
        // well as the old cert. (This is important! If we don't also have the old cert, this fails.)
        // The server is, stupidly, also sending the old, _expired_, CA root cert. This test validates that we
        // ignore the dumb server and get to the valid trust chain anyway.
        let oldCA = try NIOSSLCertificate(bytes: Array(sampleExpiredCA.utf8), format: .pem)
        let oldIntermediate = try NIOSSLCertificate(bytes: Array(sampleIntermediateCA.utf8), format: .pem)
        let newCA = try NIOSSLCertificate(bytes: Array(sampleIntermediateAsRootCA.utf8), format: .pem)
        let serverCert = try NIOSSLCertificate(bytes: Array(sampleClientOfIntermediateCA.utf8), format: .pem)
        let serverKey = try NIOSSLPrivateKey(
            bytes: Array(sampleKeyForCertificateOfClientOfIntermediateCA.utf8),
            format: .pem
        )
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.trustRoots = .certificates([newCA, oldCA])
        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(serverCert), .certificate(oldIntermediate), .certificate(oldCA)],
            privateKey: .privateKey(serverKey)
        )

        let clientContext = try NIOSSLContext(configuration: clientConfig)
        let serverContext = try NIOSSLContext(configuration: serverConfig)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().makePromise()

        let serverChannel: Channel = try serverTLSChannel(
            context: serverContext,
            handlers: [SimpleEchoServer()],
            group: group
        )
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(
            context: clientContext,
            preHandlers: [],
            postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: "localhost"
        )
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.writeString("Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testWriteSplitting() throws {
        // This test validates that we chunk writes larger than a certain value. This is an attempt
        // to regression test part of our defense against large writes, without requiring that the value end up being giant.
        let maxWriteSize = 1024
        let targetSize = (maxWriteSize * 4) + 1
        let write = ByteBuffer(repeating: 0, count: targetSize)

        let b2b = BackToBackEmbeddedChannel()

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([Self.cert])

        let serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )

        let clientContext = try assertNoThrowWithValue(NIOSSLContext(configuration: clientConfig))
        let serverContext = try assertNoThrowWithValue(NIOSSLContext(configuration: serverConfig))
        XCTAssertNoThrow(
            try b2b.client.pipeline.syncOperations.addHandler(
                try NIOSSLClientHandler(
                    context: clientContext,
                    serverHostname: "localhost",
                    optionalCustomVerificationCallbackManager: nil,
                    optionalAdditionalPeerCertificateVerificationCallback: nil,
                    maxWriteSize: maxWriteSize
                )
            )
        )
        XCTAssertNoThrow(
            try b2b.server.pipeline.syncOperations.addHandler(
                NIOSSLServerHandler(context: serverContext)
            )
        )
        XCTAssertNoThrow(try b2b.connectInMemory())

        let completed = NIOLockedValueBox(false)
        let promise = b2b.loop.makePromise(of: Void.self)
        promise.futureResult.whenComplete { _ in
            completed.withLockedValue { $0 = true }
        }

        let recordObserver = TLS13RecordObserver()
        XCTAssertNoThrow(
            try b2b.client.pipeline.syncOperations.addHandler(
                recordObserver,
                position: .first
            )
        )

        b2b.client.writeAndFlush(write, promise: promise)
        try b2b.interactInMemory()

        var reads: [ByteBuffer] = []
        while let read = try b2b.server.readInbound(as: ByteBuffer.self) {
            reads.append(read)
        }
        let totalReadBytes = reads.reduce(into: 0, { $0 += $1.readableBytes })
        XCTAssertEqual(totalReadBytes, targetSize)
        XCTAssertTrue(completed.withLockedValue { $0 })
        XCTAssertEqual(recordObserver.writtenRecords.filter { $0.contentType == .applicationData }.count, 5)

        b2b.client.close(promise: nil)
        try b2b.interactInMemory()
    }

    func testDoesNotSpinLoopWhenInactiveAndActiveAreReversed() throws {
        // This is a regression test for https://github.com/apple/swift-nio-ssl/issues/467
        //
        // If channelInactive occurs before channelActive and a re-entrant write and flush occurred
        // in channelActive then 'NIOSSLHandler.doUnbufferActions(context:)' would loop
        // indefinitely.
        let eventLoop = EmbeddedEventLoop()
        let promise = eventLoop.makePromise(of: Void.self)

        final class WriteAndFlushOnActive: ChannelInboundHandler {
            typealias InboundIn = ByteBuffer
            typealias OutboundOut = ByteBuffer

            private let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func channelActive(context: ChannelHandlerContext) {
                let buffer = context.channel.allocator.buffer(string: "You spin me right 'round")
                context.writeAndFlush(self.wrapOutboundOut(buffer), promise: self.promise)
                context.fireChannelActive()
            }
        }

        let context = try self.configuredSSLContext()
        let handler = try NIOSSLClientHandler(context: context, serverHostname: nil)
        let channel = EmbeddedChannel(
            handlers: [handler, WriteAndFlushOnActive(promise: promise)],
            loop: eventLoop
        )

        // Close _before_ channel active. This shouldn't (but can https://github.com/apple/swift-nio/issues/2773)
        // happen for 'real' channels by synchronously closing the channel when the connect promise
        // is succeeded.
        channel.pipeline.fireChannelInactive()
        channel.pipeline.fireChannelActive()

        // The handshake starts in channelActive (and handlerAdded if the channel is already
        // active). If the events are reordered then the handshake shouldn't start and there
        // shouldn't be any outbound data.
        XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self))

        // The write promise should fail.
        XCTAssertThrowsError(try promise.futureResult.wait()) { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        }

        // Subsequent writes should also fail.
        XCTAssertThrowsError(try channel.writeOutbound(ByteBuffer(string: "Like a record, baby, right 'round"))) {
            error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
        }
    }
}
