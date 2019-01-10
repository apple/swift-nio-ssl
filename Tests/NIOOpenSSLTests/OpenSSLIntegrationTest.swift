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
@testable import NIOOpenSSL
import NIOTLS
import class Foundation.Process

public func assertNoThrowWithValue<T>(_ body: @autoclosure () throws -> T, defaultValue: T? = nil, file: StaticString = #file, line: UInt = #line) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("unexpected error \(error) thrown", file: file, line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

internal func interactInMemory(clientChannel: EmbeddedChannel, serverChannel: EmbeddedChannel) throws {
    var workToDo = true
    while workToDo {
        workToDo = false
        let clientDatum = clientChannel.readOutbound()
        let serverDatum = serverChannel.readOutbound()

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

private final class SimpleEchoServer: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    
    public func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
        ctx.write(data, promise: nil)
        ctx.fireChannelRead(data)
    }
    
    public func channelReadComplete(ctx: ChannelHandlerContext) {
        ctx.flush()
        ctx.fireChannelReadComplete()
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
    
    public func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
        self.data = data
        ctx.fireChannelRead(data)
    }

    public func channelReadComplete(ctx: ChannelHandlerContext) {
        promise.succeed(result: unwrapInboundIn(data!))
        ctx.fireChannelReadComplete()
    }
}

private final class ReadRecordingHandler: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer

    private var received: ByteBuffer?
    private let completePromise: EventLoopPromise<ByteBuffer>

    init(completePromise: EventLoopPromise<ByteBuffer>) {
        self.completePromise = completePromise
    }

    func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
        var data = self.unwrapInboundIn(data)

        var newBuffer: ByteBuffer
        if var received = self.received {
            received.write(buffer: &data)
            newBuffer = received
        } else {
            newBuffer = data
        }

        self.received = newBuffer
    }

    func channelInactive(ctx: ChannelHandlerContext) {
        self.completePromise.succeed(result: self.received ?? ctx.channel.allocator.buffer(capacity: 0))
    }
}

private final class WriteCountingHandler: ChannelOutboundHandler {
    public typealias OutboundIn = Any
    public typealias OutboundOut = Any

    public var writeCount = 0

    public func write(ctx: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeCount += 1
        ctx.write(data, promise: promise)
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

        public static func ==(lhs: RecordedEvents, rhs: RecordedEvents) -> Bool {
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

    public var events: [RecordedEvents] = []

    public func channelRegistered(ctx: ChannelHandlerContext) {
        events.append(.Registered)
        ctx.fireChannelRegistered()
    }

    public func channelUnregistered(ctx: ChannelHandlerContext) {
        events.append(.Unregistered)
        ctx.fireChannelUnregistered()
    }

    public func channelActive(ctx: ChannelHandlerContext) {
        events.append(.Active)
        ctx.fireChannelActive()
    }

    public func channelInactive(ctx: ChannelHandlerContext) {
        events.append(.Inactive)
        ctx.fireChannelInactive()
    }

    public func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
        events.append(.Read)
        ctx.fireChannelRead(data)
    }

    public func channelReadComplete(ctx: ChannelHandlerContext) {
        events.append(.ReadComplete)
        ctx.fireChannelReadComplete()
    }

    public func channelWritabilityChanged(ctx: ChannelHandlerContext) {
        events.append(.WritabilityChanged)
        ctx.fireChannelWritabilityChanged()
    }

    public func userInboundEventTriggered(ctx: ChannelHandlerContext, event: Any) {
        guard let ourEvent = event as? UserEventType else {
            ctx.fireUserInboundEventTriggered(event)
            return
        }
        events.append(.UserEvent(ourEvent))
    }
}

private class ChannelActiveWaiter: ChannelInboundHandler {
    public typealias InboundIn = Any
    private var activePromise: EventLoopPromise<Void>

    public init(promise: EventLoopPromise<Void>) {
        activePromise = promise
    }

    public func channelActive(ctx: ChannelHandlerContext) {
        activePromise.succeed(result: ())
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

    func write(ctx: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writes.append((ctx, data, promise))
    }

    func forceFlush() {
        let writes = self.writes
        self.writes = []
        writes.forEach { $0.0.writeAndFlush($0.1, promise: $0.2) }
    }
}

internal func serverTLSChannel(context: NIOOpenSSL.SSLContext,
                               handlers: [ChannelHandler],
                               group: EventLoopGroup,
                               file: StaticString = #file,
                               line: UInt = #line) throws -> Channel {
    return try assertNoThrowWithValue(serverTLSChannel(context: context,
                                                       preHandlers: [],
                                                       postHandlers: handlers,
                                                       group: group,
                                                       file: file,
                                                       line: line),
                                      file: file, line: line)
}

internal func serverTLSChannel(context: NIOOpenSSL.SSLContext,
                               preHandlers: [ChannelHandler],
                               postHandlers: [ChannelHandler],
                               group: EventLoopGroup,
                               file: StaticString = #file,
                               line: UInt = #line) throws -> Channel {
    return try assertNoThrowWithValue(ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .childChannelInitializer { channel in
            let results = preHandlers.map { channel.pipeline.add(handler: $0) }
            return EventLoopFuture<Void>.andAll(results, eventLoop: results.first?.eventLoop ?? group.next()).thenThrowing {
                try OpenSSLServerHandler(context: context)
            }.then {
                channel.pipeline.add(handler: $0)
            }.then {
                let results = postHandlers.map { channel.pipeline.add(handler: $0) }
                return EventLoopFuture<Void>.andAll(results, eventLoop: results.first?.eventLoop ?? group.next())
            }
        }.bind(host: "127.0.0.1", port: 0).wait(), file: file, line: line)
}

internal func clientTLSChannel(context: NIOOpenSSL.SSLContext,
                               preHandlers: [ChannelHandler],
                               postHandlers: [ChannelHandler],
                               group: EventLoopGroup,
                               connectingTo: SocketAddress,
                               serverHostname: String? = nil,
                               verificationCallback: OpenSSLVerificationCallback? = nil,
                               file: StaticString = #file,
                               line: UInt = #line) throws -> Channel {
    return try assertNoThrowWithValue(ClientBootstrap(group: group)
        .channelInitializer { channel in
            let results = preHandlers.map { channel.pipeline.add(handler: $0) }
            return EventLoopFuture<Void>.andAll(results, eventLoop: results.first?.eventLoop ?? group.next()).thenThrowing {
                try OpenSSLClientHandler(context: context, serverHostname: serverHostname, verificationCallback: verificationCallback)
            }.then {
                channel.pipeline.add(handler: $0)
            }.then {
                let results = postHandlers.map { channel.pipeline.add(handler: $0) }
                return EventLoopFuture<Void>.andAll(results, eventLoop: results.first?.eventLoop ?? group.next())
            }
        }.connect(to: connectingTo).wait(), file: file, line: line)
}

class OpenSSLIntegrationTest: XCTestCase {
    static var cert: OpenSSLCertificate!
    static var key: OpenSSLPrivateKey!
    static var encryptedKeyPath: String!
    
    override class func setUp() {
        super.setUp()
        guard openSSLIsInitialized else { fatalError() }
        let (cert, key) = generateSelfSignedCert()
        OpenSSLIntegrationTest.cert = cert
        OpenSSLIntegrationTest.key = key
        OpenSSLIntegrationTest.encryptedKeyPath = keyInFile(key: OpenSSLIntegrationTest.key, passphrase: "thisisagreatpassword")
    }

    override class func tearDown() {
        _ = unlink(OpenSSLIntegrationTest.encryptedKeyPath)
    }
    
    private func configuredSSLContext(file: StaticString = #file, line: UInt = #line) throws -> NIOOpenSSL.SSLContext {
        let config = TLSConfiguration.forServer(certificateChain: [.certificate(OpenSSLIntegrationTest.cert)],
                                                privateKey: .privateKey(OpenSSLIntegrationTest.key),
                                                trustRoots: .certificates([OpenSSLIntegrationTest.cert]))
        return try assertNoThrowWithValue(SSLContext(configuration: config), file: file, line: line)
    }

    private func configuredSSLContext<T: Collection>(passphraseCallback: @escaping OpenSSLPassphraseCallback<T>,
                                                     file: StaticString = #file, line: UInt = #line) throws -> NIOOpenSSL.SSLContext
                                                     where T.Element == UInt8 {
        let config = TLSConfiguration.forServer(certificateChain: [.certificate(OpenSSLIntegrationTest.cert)],
                                                privateKey: .file(OpenSSLIntegrationTest.encryptedKeyPath),
                                                trustRoots: .certificates([OpenSSLIntegrationTest.cert]))
        return try assertNoThrowWithValue(SSLContext(configuration: config, passphraseCallback: passphraseCallback), file: file, line: line)
    }

    private func configuredClientContext(file: StaticString = #file, line: UInt = #line) throws -> NIOOpenSSL.SSLContext {
        let config = TLSConfiguration.forClient(trustRoots: .certificates([OpenSSLIntegrationTest.cert]))
        return try assertNoThrowWithValue(SSLContext(configuration: config), file: file, line: line)
    }

    static func keyInFile(key: OpenSSLPrivateKey, passphrase: String) -> String {
        let fileName = makeTemporaryFile(fileExtension: ".pem")
        let tempFile = open(fileName, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
        precondition(tempFile > 1, String(cString: strerror(errno)))
        let fileBio = BIO_new_fp(fdopen(tempFile, "w+"), BIO_CLOSE)
        precondition(fileBio != nil)

        let manager = OpenSSLPassphraseCallbackManager { closure in closure(passphrase.utf8) }
        let rc = withExtendedLifetime(manager) { manager -> CInt in
            let userData = Unmanaged.passUnretained(manager).toOpaque()
            return PEM_write_bio_PrivateKey(fileBio, .make(optional: key.ref), EVP_aes_256_cbc(), nil, 0, globalOpenSSLPassphraseCallback, userData)
        }
        BIO_free(fileBio)
        precondition(rc == 1)
        return fileName
    }

    func withTrustBundleInFile<T>(tempFile fileName: inout String?, fn: (String) throws -> T) throws -> T {
        fileName = makeTemporaryFile()
        guard let fileName = fileName else {
            fatalError("couldn't make temp file")
        }
        let tempFile = fileName.withCString { ptr in
            return open(ptr, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
        }
        precondition(tempFile > 1, String(cString: strerror(errno)))
        let fileBio = BIO_new_fp(fdopen(tempFile, "w+"), BIO_CLOSE)
        precondition(fileBio != nil)

        let rc = PEM_write_bio_X509(fileBio, .make(optional: OpenSSLIntegrationTest.cert.ref))
        BIO_free(fileBio)
        precondition(rc == 1)
        return try fn(fileName)
    }
    
    func testSimpleEcho() throws {
        let ctx = try configuredSSLContext()
        
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }
        
        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()

        let serverChannel: Channel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }
        
        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }
        
        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()
        
        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testHandshakeEventSequencing() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let readComplete: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let serverHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let serverChannel = try serverTLSChannel(context: ctx,
                                                 handlers: [serverHandler, PromiseOnReadHandler(promise: readComplete)],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [SimpleEchoServer()],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
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
            .ReadComplete
        ]

        XCTAssertEqual(expectedEvents, serverHandler.events)
    }

    func testShutdownEventSequencing() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let readComplete: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let serverHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let serverChannel = try serverTLSChannel(context: ctx,
                                                 handlers: [serverHandler, PromiseOnReadHandler(promise: readComplete)],
                                                 group: group)

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [SimpleEchoServer()],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        // Ok, we want to wait for the read to finish, then close the server and client connections.
        _ = try readComplete.futureResult.then { (_: ByteBuffer) in
            return serverChannel.close()
        }.then {
            return clientChannel.close()
        }.wait()

        let expectedEvents: [EventRecorderHandler<TLSUserEvent>.RecordedEvents] = [
            .Registered,
            .Active,
            .UserEvent(TLSUserEvent.handshakeCompleted(negotiatedProtocol: nil)),
            .Read,
            .ReadComplete,
            .UserEvent(TLSUserEvent.shutdownCompleted),
            .Inactive,
            .Unregistered
        ]

        XCTAssertEqual(expectedEvents, serverHandler.events)
    }

    func testMultipleClose() throws {
        var serverClosed = false
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()

        let serverChannel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            if !serverClosed {
                XCTAssertNoThrow(try serverChannel.close().wait())
            }
        }

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
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
        let promises: [EventLoopPromise<Void>] = [group.next().newPromise(), group.next().newPromise(), group.next().newPromise()]
        group.next().execute {
            for promise in promises {
                serverChannel.close(promise: promise)
            }
        }

        XCTAssertNoThrow(try promises.first!.futureResult.wait())
        serverClosed = true

        for promise in promises {
            // This should never block, but it may throw because the I/O is complete.
            do {
                _ = try promise.futureResult.wait()
            } catch {
                // Suppress all errors, they're fine.
            }
        }
    }

    func testCoalescedWrites() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let recorderHandler = EventRecorderHandler<TLSUserEvent>()
        let serverChannel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let writeCounter = WriteCountingHandler()
        let readPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [writeCounter],
                                                 postHandlers: [PromiseOnReadHandler(promise: readPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // We're going to issue a number of small writes. Each of these should be coalesced together
        // such that the underlying layer sees only one write for them. The total number of
        // writes should be (after we flush) 3: one for Client Hello, one for Finished, and one
        // for the coalesced writes.
        var originalBuffer = clientChannel.allocator.buffer(capacity: 1)
        originalBuffer.write(string: "A")
        var writeFutures: [EventLoopFuture<()>] = []
        for _ in 0..<5 {
            writeFutures.append(clientChannel.write(NIOAny(originalBuffer)))
        }

        clientChannel.flush()
        try EventLoopFuture<()>.andAll(writeFutures, eventLoop: clientChannel.eventLoop).wait()
        let writeCount = try readPromise.futureResult.map { (_: ByteBuffer) in
            // Here we're in the I/O loop, so we know that no further channel action will happen
            // while we dispatch this callback. This is the perfect time to check how many writes
            // happened.
            return writeCounter.writeCount
        }.wait()
        XCTAssertEqual(writeCount, 3)
    }

    func testCoalescedWritesWithFutures() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let recorderHandler = EventRecorderHandler<TLSUserEvent>()
        let serverChannel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        // We're going to issue a number of small writes. Each of these should be coalesced together
        // and all their futures (along with the one for the flush) should fire, in order, with nothing
        // missed.
        var firedFutures: Array<Int> = []
        var writeFutures: [EventLoopFuture<()>] = []
        var originalBuffer = clientChannel.allocator.buffer(capacity: 1)
        originalBuffer.write(string: "A")
        for index in 0..<5 {
            let promise: EventLoopPromise<Void> = group.next().newPromise()
            writeFutures.append(promise.futureResult)
            promise.futureResult.map {
                XCTAssertEqual(firedFutures.count, index)
                firedFutures.append(index)
            }.whenFailure { error in
                XCTFail("Write promise failed: \(error)")
            }
            clientChannel.write(NIOAny(originalBuffer), promise: promise)
        }

        clientChannel.flush()
        try EventLoopFuture<()>.andAll(writeFutures, eventLoop: clientChannel.eventLoop).map {
            XCTAssertEqual(firedFutures, [0, 1, 2, 3, 4])
        }.mapIfError { error in
            XCTFail("Write promised failed: \(error)")
        }.wait()
    }

    func testImmediateCloseSatisfiesPromises() throws {
        let ctx = try configuredSSLContext()
        let channel = EmbeddedChannel()
        try channel.pipeline.add(handler: OpenSSLClientHandler(context: ctx)).wait()

        // Start by initiating the handshake.
        try channel.connect(to: SocketAddress(unixDomainSocketPath: "/tmp/doesntmatter")).wait()

        // Now call close. This should immediately close, satisfying the promise.
        let closePromise: EventLoopPromise<Void> = channel.eventLoop.newPromise()
        channel.close(promise: closePromise)

        XCTAssertNoThrow(try closePromise.futureResult.wait())
    }

    func testAddingTlsToActiveChannelStillHandshakes() throws {
        let ctx = try configuredSSLContext()
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let recorderHandler: EventRecorderHandler<TLSUserEvent> = EventRecorderHandler()
        let channelActiveWaiter = ChannelActiveWaiter(promise: group.next().newPromise())
        let serverChannel = try serverTLSChannel(context: ctx,
                                                 handlers: [recorderHandler, SimpleEchoServer(), channelActiveWaiter],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        // Create a client channel without TLS in it, and connect it.
        let readPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let promiseOnReadHandler = PromiseOnReadHandler(promise: readPromise)
        let clientChannel = try ClientBootstrap(group: group)
            .channelInitializer({ $0.pipeline.add(handler: promiseOnReadHandler) })
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
        try clientChannel.pipeline.add(name: nil, handler: OpenSSLClientHandler(context: ctx), first: true).wait()
        var data = clientChannel.allocator.buffer(capacity: 1)
        data.write(staticString: "x")
        try clientChannel.writeAndFlush(data).wait()

        // The echo should come back without error.
        _ = try readPromise.futureResult.wait()

        // At this point the handshake should be complete.
        try group.next().submit {
            XCTAssertEqual(recorderHandler.events[..<3], [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))])
        }.wait()
    }

    func testValidatesHostnameOnConnectionFails() throws {
        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let serverChannel = try serverTLSChannel(context: serverCtx,
                                                 handlers: [],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOOpenSSLError>()
        let clientChannel = try clientTLSChannel(context: clientCtx,
                                                 preHandlers: [],
                                                 postHandlers: [errorHandler],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOOpenSSLError]> = writeFuture.mapIfError { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            return ()
        }.map {
            return errorHandler.errors
        }
        let actualErrors = try errorsFuture.wait()

        // This write will have failed, but that's fine: we just want it as a signal that
        // the handshake is done so we can make our assertions.
        let expectedErrors: [NIOOpenSSLError] = [NIOOpenSSLError.unableToValidateCertificate]

        XCTAssertEqual(expectedErrors, actualErrors)
    }

    func testValidatesHostnameOnConnectionSucceeds() throws {
        let serverCtx = try configuredSSLContext()
        let clientCtx = try configuredClientContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(context: serverCtx,
                                                 handlers: [],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let eventHandler = EventRecorderHandler<TLSUserEvent>()
        let clientChannel = try clientTLSChannel(context: clientCtx,
                                                 preHandlers: [],
                                                 postHandlers: [eventHandler],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 serverHostname: "localhost")

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        writeFuture.whenComplete {
            XCTAssertEqual(eventHandler.events[..<3], [.Registered, .Active, .UserEvent(.handshakeCompleted(negotiatedProtocol: nil))])
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

        let ctx = try configuredSSLContext()

        try serverChannel.pipeline.add(handler: try OpenSSLServerHandler(context: ctx)).wait()
        try clientChannel.pipeline.add(handler: try OpenSSLClientHandler(context: ctx)).wait()

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
        closePromise.whenComplete {
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
            case let e as OpenSSLError where e == .uncleanShutdown:
                break
            default:
                XCTFail("Unexpected error: \(error)")
            }
        }

        // Now clean up the client channel. We need to also fire the channel inactive here as there is
        // no-one left for the client channel to hang up on.
        _ = clientChannel.close()
        clientChannel.pipeline.fireChannelInactive()
    }

    func testTrustStoreOnDisk() throws {
        var tempFile: String? = nil
        let serverCtx = try configuredSSLContext()
        let config = try withTrustBundleInFile(tempFile: &tempFile) {
            return TLSConfiguration.forClient(certificateVerification: .noHostnameVerification,
                                              trustRoots: .file($0),
                                              certificateChain: [.certificate(OpenSSLIntegrationTest.cert)],
                                              privateKey: .privateKey(OpenSSLIntegrationTest.key))
        }
        defer {
            precondition(.some(0) == tempFile.map { unlink($0) }, "couldn't remove temp file \(tempFile.debugDescription)")
        }
        let clientCtx = try assertNoThrowWithValue(SSLContext(configuration: config))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()
        let serverChannel: Channel = try serverTLSChannel(context: serverCtx, handlers: [SimpleEchoServer()], group: group)
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(context: clientCtx,
                                                 preHandlers: [],
                                                 postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            _ = try? clientChannel.close().wait()
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")

        try clientChannel.writeAndFlush(originalBuffer).wait()
        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testChecksTrustStoreOnDisk() throws {
        let serverCtx = try configuredSSLContext()
        let clientConfig = TLSConfiguration.forClient(certificateVerification: .noHostnameVerification,
                                                      trustRoots: .file("/tmp"),
                                                      certificateChain: [.certificate(OpenSSLIntegrationTest.cert)],
                                                      privateKey: .privateKey(OpenSSLIntegrationTest.key))
        let clientCtx = try assertNoThrowWithValue(SSLContext(configuration: clientConfig))

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel = try serverTLSChannel(context: serverCtx,
                                                 handlers: [],
                                                 group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOOpenSSLError>()
        let clientChannel = try clientTLSChannel(context: clientCtx,
                                                 preHandlers: [],
                                                 postHandlers: [errorHandler],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOOpenSSLError]> = writeFuture.mapIfError { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            return ()
        }.map {
            return errorHandler.errors
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

        let ctx = try configuredSSLContext()

        try serverChannel.pipeline.add(handler: try OpenSSLServerHandler(context: ctx)).wait()
        try clientChannel.pipeline.add(handler: try OpenSSLClientHandler(context: ctx)).wait()

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
        closePromise.whenComplete {
            var buffer = serverChannel.allocator.buffer(capacity: 5)
            buffer.write(staticString: "hello")
            serverChannel.pipeline.fireChannelRead(NIOAny(buffer))
            serverChannel.pipeline.fireChannelReadComplete()
        }

        do {
            try serverChannel.throwIfErrorCaught()
        } catch {
            XCTFail("Already has error: \(error)")
        }

        do {
            try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
            XCTFail("Did not cause error")
        } catch NIOOpenSSLError.readInInvalidTLSState {
            // Nothing to do here.
        } catch {
            XCTFail("Encountered unexpected error: \(error)")
        }
    }

    func testZeroLengthWrite() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()

        let serverChannel = try serverTLSChannel(context: ctx,
                                                 handlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group)
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            _ = try? clientChannel.close().wait()
        }

        // Write several zero-length buffers *and* one with some actual data. Only one should
        // be written.
        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        let promises = (0...5).map { (_: Int) in clientChannel.write(originalBuffer) }
        originalBuffer.write(staticString: "hello")
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

        let ctx = try configuredSSLContext()

        try serverChannel.pipeline.add(handler: try OpenSSLServerHandler(context: ctx)).wait()
        try clientChannel.pipeline.add(handler: try OpenSSLClientHandler(context: ctx)).wait()

        let addr = try SocketAddress(unixDomainSocketPath: "/tmp/whatever2")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()

        // This test fires three writes, flushing between them all. We want to confirm that all of the
        // writes are succeeded in order. To do that, we want to add a WriteDelayHandler to
        // prevent the EmbeddedChannel succeeding the early writes.
        let writeDelayer = WriteDelayHandler()
        try clientChannel.pipeline.add(handler: writeDelayer, first: true).wait()
        var writeCount = 0
        let emptyBuffer = clientChannel.allocator.buffer(capacity: 16)
        var buffer = clientChannel.allocator.buffer(capacity: 16)
        buffer.write(staticString: "hello world")

        clientChannel.write(buffer).whenComplete {
            XCTAssertEqual(writeCount, 0)
            writeCount = 1
        }
        clientChannel.flush()
        clientChannel.write(emptyBuffer).whenComplete {
            XCTAssertEqual(writeCount, 1)
            writeCount = 2
        }
        clientChannel.flush()
        clientChannel.write(buffer).whenComplete {
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
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()

        let serverChannel: Channel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let clientChannel = try clientTLSChannel(context: ctx,
                                                 preHandlers: [],
                                                 postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!)
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        try clientChannel.writeAndFlush(originalBuffer).wait()

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)
    }

    func testFlushPendingReadsOnCloseNotify() throws {
        let ctx = try assertNoThrowWithValue(configuredSSLContext())
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()
        defer {
            _ = try? serverChannel.finish()
            _ = try? clientChannel.finish()
        }

        let completePromise: EventLoopPromise<ByteBuffer> = serverChannel.eventLoop.newPromise()

        XCTAssertNoThrow(try serverChannel.pipeline.add(handler: try OpenSSLServerHandler(context: ctx)).wait())
        XCTAssertNoThrow(try serverChannel.pipeline.add(handler: ReadRecordingHandler(completePromise: completePromise)).wait())
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: try OpenSSLClientHandler(context: ctx)).wait())

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
        originalBuffer.write(string: "Hello")
        clientChannel.writeAndFlush(originalBuffer, promise: nil)
        let clientClosePromise = clientChannel.close()

        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        while case .some(.byteBuffer(var data)) = clientChannel.readOutbound() {
            buffer.write(buffer: &data)
        }
        XCTAssertNoThrow(try serverChannel.writeInbound(buffer))

        // Now we can interact. The server should close.
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertNoThrow(try clientClosePromise.wait())

        // Now check what we read.
        var readData = try assertNoThrowWithValue(completePromise.futureResult.wait())
        XCTAssertEqual(readData.readString(length: readData.readableBytes)!, "Hello")
    }

    func testForcingVerificationFailure() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let serverChannel: Channel = try serverTLSChannel(context: ctx, handlers: [], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        let errorHandler = ErrorCatcher<NIOOpenSSLError>()
        let clientChannel = try clientTLSChannel(context: try configuredClientContext(),
                                                 preHandlers: [],
                                                 postHandlers: [errorHandler],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 verificationCallback: { preverify, certificate in
                                                    XCTAssertEqual(preverify, .certificateVerified)
                                                    return .failed
        })

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        let writeFuture = clientChannel.writeAndFlush(originalBuffer)
        let errorsFuture: EventLoopFuture<[NIOOpenSSLError]> = writeFuture.mapIfError { (_: Error) in
            // We're swallowing errors here, on purpose, because we'll definitely
            // hit them.
            return ()
        }.map {
            return errorHandler.errors
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

    func testExtractingCertificates() throws {
        let ctx = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            XCTAssertNoThrow(try group.syncShutdownGracefully())
        }

        let completionPromise: EventLoopPromise<ByteBuffer> = group.next().newPromise()

        let serverChannel: Channel = try serverTLSChannel(context: ctx, handlers: [SimpleEchoServer()], group: group)
        defer {
            XCTAssertNoThrow(try serverChannel.close().wait())
        }

        var certificates = [OpenSSLCertificate]()
        let clientChannel = try clientTLSChannel(context: configuredClientContext(),
                                                 preHandlers: [],
                                                 postHandlers: [PromiseOnReadHandler(promise: completionPromise)],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 serverHostname: "localhost",
                                                 verificationCallback: { verify, certificate in
                                                    certificates.append(certificate)
                                                    return verify
        })
        defer {
            XCTAssertNoThrow(try clientChannel.close().wait())
        }

        var originalBuffer = clientChannel.allocator.buffer(capacity: 5)
        originalBuffer.write(string: "Hello")
        XCTAssertNoThrow(try clientChannel.writeAndFlush(originalBuffer).wait())

        let newBuffer = try completionPromise.futureResult.wait()
        XCTAssertEqual(newBuffer, originalBuffer)

        XCTAssertEqual(certificates.count, 1)
    }

    func testRepeatedClosure() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect both cases to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let ctx = try assertNoThrowWithValue(configuredSSLContext())

        XCTAssertNoThrow(try serverChannel.pipeline.add(handler: OpenSSLServerHandler(context: ctx)).wait())
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: OpenSSLClientHandler(context: ctx)).wait())
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // We're going to close twice: the first one without a promise, the second one with one.
        var closed = false
        clientChannel.close(promise: nil)
        clientChannel.close().whenComplete {
            closed = true
        }
        XCTAssertFalse(closed)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        // The closure should have happened.
        XCTAssertTrue(closed)
    }

    func testReceivingGibberishAfterAttemptingToClose() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false

        defer {
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let ctx = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(OpenSSLClientHandler(context: ctx))
        XCTAssertNoThrow(try serverChannel.pipeline.add(handler: OpenSSLServerHandler(context: ctx)).wait())
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: clientHandler).wait())
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: handshakeHandler).wait())

        // Mark the closure of the client.
        clientChannel.closeFuture.whenComplete {
            clientClosed = true
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
        XCTAssertFalse(clientClosed)

        // Now we're going to simulate the client receiving gibberish data in response, instead
        // of a CLOSE_NOTIFY.
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.write(staticString: "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")

        do {
            try clientChannel.writeInbound(buffer)
            XCTFail("Did not error")
        } catch NIOOpenSSLError.shutdownFailed {
            // expected
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertTrue(clientClosed)

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

        let ctx = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(OpenSSLClientHandler(context: ctx))
        XCTAssertNoThrow(try serverChannel.pipeline.add(handler: OpenSSLServerHandler(context: ctx)).wait())
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: clientHandler).wait())
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.add(handler: handshakeHandler).wait())

        // Connect. This should lead to a completed handshake.
        let addr: SocketAddress = try SocketAddress(unixDomainSocketPath: "/tmp/whatever")
        let connectFuture = clientChannel.connect(to: addr)
        serverChannel.pipeline.fireChannelActive()
        try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        try connectFuture.wait()
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Queue up a write.
        var writeCompleted = false
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.write(staticString: "Hello, world!")
        clientChannel.write(buffer).map {
            XCTFail("Must not succeed")
            }.whenFailure { error in
                XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
                writeCompleted = true
        }

        // We haven't spun the event loop, so the handlers are still in the pipeline. Now attempt to close.
        var closed = false
        clientChannel.closeFuture.whenComplete {
            closed = true
        }

        XCTAssertFalse(writeCompleted)
        clientChannel.close(promise: nil)
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertFalse(writeCompleted)
        XCTAssertFalse(closed)

        // Now try to flush the write. This should fail the write early, and take out the connection.
        clientChannel.flush()
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertTrue(writeCompleted)
        XCTAssertTrue(closed)

        // Bring the server up to speed.
        serverChannel.pipeline.fireChannelInactive()
    }
}
