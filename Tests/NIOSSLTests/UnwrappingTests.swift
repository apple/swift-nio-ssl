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
import XCTest

@testable import NIOSSL

func connectInMemory(client: EmbeddedChannel, server: EmbeddedChannel) throws {
    let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
    let connectFuture = client.connect(to: addr)
    server.pipeline.fireChannelActive()
    XCTAssertNoThrow(try interactInMemory(clientChannel: client, serverChannel: server))
    XCTAssertNoThrow(try connectFuture.wait())
}

extension ChannelPipeline.SynchronousOperations {
    func assertContains(handler: ChannelHandler, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try self.context(handler: handler)
        } catch {
            XCTFail("Handler \(handler) missing from \(self)", file: (file), line: line)
        }
    }

    func assertDoesNotContain(handler: ChannelHandler, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try self.context(handler: handler)
            XCTFail("Handler \(handler) present in \(self)", file: (file), line: line)
        } catch {
            // Expected
        }
    }
}

final class UnwrappingTests: XCTestCase {
    static let _certAndKey = generateSelfSignedCert()
    static let cert = UnwrappingTests._certAndKey.0
    static let key = UnwrappingTests._certAndKey.1

    private func configuredSSLContext(file: StaticString = #filePath, line: UInt = #line) throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(UnwrappingTests.cert)],
            privateKey: .privateKey(UnwrappingTests.key)
        )
        config.trustRoots = .certificates([UnwrappingTests.cert])
        return try assertNoThrowWithValue(NIOSSLContext(configuration: config), file: file, line: line)
    }

    func testSimpleUnwrapping() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var serverClosed = false
        var unwrapped = false

        defer {
            // We expect the server case to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the channels.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }
        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection. With no additional configuration, this will cause the server
        // to close. The client will not close because interactInMemory does not propagate closure.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { _ in
            unwrapped = true
        }
        clientHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)

        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        clientChannel.pipeline.syncOperations.assertDoesNotContain(handler: clientHandler)

        (serverChannel.eventLoop as! EmbeddedEventLoop).run()
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()

        XCTAssertFalse(clientClosed)
        XCTAssertTrue(serverClosed)
        XCTAssertTrue(unwrapped)
    }

    func testSimultaneousUnwrapping() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var serverClosed = false
        var clientUnwrapped = false
        var serverUnwrapped = false

        defer {
            XCTAssertNoThrow(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        let serverHandler = try assertNoThrowWithValue(NIOSSLServerHandler(context: context))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(serverHandler))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the channels.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }
        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection and the server connection at the same time. This should
        // not close either channel.
        let clientStopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientStopPromise.futureResult.assumeIsolated().whenComplete { _ in
            clientUnwrapped = true
        }
        clientHandler.stopTLS(promise: clientStopPromise)

        let serverStopPromise: EventLoopPromise<Void> = serverChannel.eventLoop.makePromise()
        serverStopPromise.futureResult.assumeIsolated().whenComplete { _ in
            serverUnwrapped = true
        }
        serverHandler.stopTLS(promise: serverStopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(clientUnwrapped)
        XCTAssertFalse(serverUnwrapped)

        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        clientChannel.pipeline.syncOperations.assertDoesNotContain(handler: clientHandler)
        serverChannel.pipeline.syncOperations.assertDoesNotContain(handler: serverHandler)

        (serverChannel.eventLoop as! EmbeddedEventLoop).run()
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertTrue(clientUnwrapped)
        XCTAssertTrue(serverUnwrapped)
    }

    func testUnwrappingFollowedByClosure() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var clientUnwrapped = false

        defer {
            // Both channels will already be closed
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the client.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection.
        let clientStopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientStopPromise.futureResult.assumeIsolated().map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            XCTAssertEqual(error as? NIOTLSUnwrappingError, NIOTLSUnwrappingError.closeRequestedDuringUnwrap)
            clientUnwrapped = true
        }
        clientHandler.stopTLS(promise: clientStopPromise)

        // Now we're going to close the client.
        clientChannel.close().assumeIsolated().whenComplete { _ in
            XCTAssertFalse(clientClosed)
            XCTAssertTrue(clientUnwrapped)
        }

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(clientUnwrapped)

        XCTAssertNoThrow(
            try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel, runLoops: false)
        )
        clientChannel.pipeline.syncOperations.assertContains(handler: clientHandler)

        (serverChannel.eventLoop as! EmbeddedEventLoop).run()
        (clientChannel.eventLoop as! EmbeddedEventLoop).run()

        XCTAssertTrue(clientClosed)
        XCTAssertTrue(clientUnwrapped)
    }

    func testUnwrappingMeetsTCPFIN() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var clientUnwrapped = false

        defer {
            // The errors here are expected
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the client.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection.
        let clientStopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientStopPromise.futureResult.assumeIsolated().map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            XCTAssertEqual(error as? NIOSSLError, .uncleanShutdown)
            clientUnwrapped = true
        }
        clientHandler.stopTLS(promise: clientStopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(clientUnwrapped)

        // Now we're going to simulate the client receiving a TCP FIN the other way.
        clientChannel.pipeline.fireChannelInactive()
        clientChannel.pipeline.syncOperations.assertContains(handler: clientHandler)

        (clientChannel.eventLoop as! EmbeddedEventLoop).run()
        XCTAssertTrue(clientUnwrapped)

        // Clean up by bringing the server up to speed
        serverChannel.pipeline.fireChannelInactive()
    }

    func testDoubleUnwrapping() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var promiseCalled = false

        defer {
            // We expect the server case to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection twice. We'll ignore the first promise.
        let dummyPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { _ in
            promiseCalled = true
        }
        clientHandler.stopTLS(promise: dummyPromise)
        clientHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(promiseCalled)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertTrue(promiseCalled)
    }

    func testUnwrappingAfterIgnoredUnwrapping() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var promiseCalled = false

        defer {
            // We expect the server case to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection twice. We'll only send a promise the second time.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { _ in
            promiseCalled = true
        }
        clientHandler.stopTLS(promise: nil)
        clientHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(promiseCalled)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertTrue(promiseCalled)
    }

    func testUnwrappingIdleChannel() throws {
        let channel = EmbeddedChannel()

        var promiseCalled = false

        defer {
            XCTAssertNoThrow(try channel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let handler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))
        channel.pipeline.syncOperations.assertContains(handler: handler)

        // Let's unwrap. This should succeed easily.
        let stopPromise: EventLoopPromise<Void> = channel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { _ in
            promiseCalled = true
        }

        XCTAssertFalse(promiseCalled)
        handler.stopTLS(promise: stopPromise)
        XCTAssertTrue(promiseCalled)
    }

    func testUnwrappingAfterSuccessfulUnwrap() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var promiseCalled = false

        defer {
            // We expect the server case to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { _ in
            promiseCalled = true
        }
        clientHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(promiseCalled)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertTrue(promiseCalled)

        // Now, let's unwrap it again.
        let secondPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientHandler.stopTLS(promise: secondPromise)
        do {
            try secondPromise.futureResult.wait()
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testUnwrappingAfterClosure() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect both casees to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's close everything down.
        clientChannel.close(promise: nil)
        serverChannel.close(promise: nil)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        // We haven't spun the event loop, so the handlers are still in the pipeline. Now attempt to unwrap.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientHandler.stopTLS(promise: stopPromise)

        XCTAssertThrowsError(try stopPromise.futureResult.wait()) { error in
            XCTAssertEqual(.some(.alreadyClosed), error as? NIOTLSUnwrappingError)
        }
    }

    func testReceivingGibberishAfterAttemptingToUnwrap() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var clientUnwrapped = false

        defer {
            // The errors here are expected
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the client.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection.
        let clientStopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        clientStopPromise.futureResult.assumeIsolated().map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            switch error as? NIOSSLError {
            case .some(.shutdownFailed):
                // Expected
                break
            default:
                XCTFail("Unexpected error: \(error)")
            }

            clientUnwrapped = true
        }
        clientHandler.stopTLS(promise: clientStopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(clientUnwrapped)

        // Now we're going to simulate the client receiving gibberish data in response, instead
        // of a CLOSE_NOTIFY.
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeStaticString("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")

        XCTAssertThrowsError(try clientChannel.writeInbound(buffer)) { error in
            switch error as? NIOSSLError {
            case .some(.shutdownFailed):
                // Expected
                break
            default:
                XCTFail("Unexpected error: \(error)")
            }
        }

        // The client should have errored out now. The handler should still be there, as unwrapping
        // has failed.
        XCTAssertTrue(clientUnwrapped)
        clientChannel.pipeline.syncOperations.assertContains(handler: clientHandler)

        // Clean up by bringing the server up to speed
        serverChannel.pipeline.fireChannelInactive()
    }

    func testPendingWritesFailOnUnwrap() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Queue up a write.
        var writeCompleted = false
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeStaticString("Hello, world!")
        clientChannel.write(buffer).assumeIsolated().map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            XCTAssertEqual(error as? NIOTLSUnwrappingError, .unflushedWriteOnUnwrap)
            writeCompleted = true
        }

        // We haven't spun the event loop, so the handlers are still in the pipeline. Now attempt to unwrap.
        var unwrapped = false
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenSuccess {
            XCTAssertTrue(writeCompleted)
            unwrapped = true
        }
        XCTAssertFalse(writeCompleted)
        clientHandler.stopTLS(promise: stopPromise)
        XCTAssertFalse(writeCompleted)
        XCTAssertFalse(unwrapped)

        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))
        XCTAssertTrue(writeCompleted)
        XCTAssertTrue(unwrapped)
    }

    func testPendingWritesFailWhenFlushedOnUnwrap() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect both cases to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Queue up a write.
        var writeCompleted = false
        var buffer = clientChannel.allocator.buffer(capacity: 1024)
        buffer.writeStaticString("Hello, world!")
        clientChannel.write(buffer).assumeIsolated().map {
            XCTFail("Must not succeed")
        }.whenFailure { error in
            XCTAssertEqual(error as? ChannelError, .ioOnClosedChannel)
            writeCompleted = true
        }

        // We haven't spun the event loop, so the handlers are still in the pipeline. Now attempt to unwrap.
        var unwrapped = false
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenFailure { error in
            switch error as? BoringSSLError {
            case .some(.sslError):
                // ok
                break
            default:
                XCTFail("Unexpected error: \(error)")
            }
            unwrapped = true
        }
        XCTAssertFalse(writeCompleted)
        clientHandler.stopTLS(promise: stopPromise)
        XCTAssertFalse(writeCompleted)
        XCTAssertFalse(unwrapped)

        // Now try to flush the write. This should fail the write early, and take out the connection.
        clientChannel.flush()
        XCTAssertTrue(writeCompleted)
        XCTAssertTrue(unwrapped)

        // Bring the server up to speed.
        serverChannel.pipeline.fireChannelInactive()
    }

    func testDataReceivedAfterCloseNotifyIsPassedDownThePipeline() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        defer {
            // We expect the server case to throw
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertNoThrow(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))
        let readPromise: EventLoopPromise<ByteBuffer> = clientChannel.eventLoop.makePromise()
        XCTAssertNoThrow(
            try clientChannel.pipeline.syncOperations.addHandler(PromiseOnReadHandler(promise: readPromise))
        )

        var readCompleted = false
        readPromise.futureResult.assumeIsolated().whenSuccess { buffer in
            XCTAssertEqual(buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes), "Hello, world!")
            readCompleted = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the client connection. With no additional configuration, this will cause the server
        // to close. The client will not close because interactInMemory does not propagate closure.
        var unwrapped = false
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenSuccess {
            unwrapped = true
        }
        clientHandler.stopTLS(promise: stopPromise)

        // Now we want to manually handle the interaction. The client will have sent a CLOSE_NOTIFY: send it to the server.
        let clientCloseNotify = try clientChannel.readOutbound(as: ByteBuffer.self)!
        XCTAssertNoThrow(try serverChannel.writeInbound(clientCloseNotify))

        // The server will have sent a CLOSE_NOTIFY: grab it.
        var serverCloseNotify = try serverChannel.readOutbound(as: ByteBuffer.self)!

        // We're going to append some plaintext data.
        serverCloseNotify.writeStaticString("Hello, world!")

        // Now we're going to send it to the client.
        XCTAssertFalse(unwrapped)
        XCTAssertFalse(readCompleted)
        XCTAssertNoThrow(try clientChannel.writeInbound(serverCloseNotify))

        // This will have triggered an unwrap.
        XCTAssertTrue(unwrapped)

        // We should also have received the plaintext data.
        XCTAssertTrue(readCompleted)
    }

    func testUnwrappingTimeout() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var serverClosed = false
        var unwrapped = false

        defer {
            XCTAssertNoThrow(try serverChannel.finish(acceptAlreadyClosed: false))
            XCTAssertNoThrow(try clientChannel.finish(acceptAlreadyClosed: false))
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let serverHandler = try assertNoThrowWithValue(NIOSSLServerHandler(context: context))
        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(serverHandler))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the channels.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }
        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the server connection. We are not going to interact in memory, because we want to simulate a
        // timeout.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { result in
            unwrapped = true

            switch result {
            case .success:
                XCTFail("Shutdown succeeded unexpectedly")
            case .failure(let err):
                XCTAssertTrue(err is NIOSSLCloseTimedOutError, "Unexpected error: \(err)")
            }
        }
        serverHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)
        XCTAssertNoThrow(try serverChannel.throwIfErrorCaught())

        // Advance time by 5 seconds. This should fire the timeout. We unwrap. The connection is not closed automatically.
        serverChannel.embeddedEventLoop.advanceTime(by: .seconds(5))
        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertTrue(unwrapped)
        serverChannel.pipeline.syncOperations.assertDoesNotContain(handler: serverHandler)
        XCTAssertThrowsError(try serverChannel.throwIfErrorCaught()) { error in
            XCTAssertTrue(error is NIOSSLCloseTimedOutError, "Unexpected error: \(error)")
        }

        // Now we do the same for the client to get it out of the pipeline too. Naturally, it'll time out.
        clientHandler.stopTLS(promise: nil)
        clientChannel.embeddedEventLoop.advanceTime(by: .seconds(5))
        clientChannel.pipeline.syncOperations.assertDoesNotContain(handler: clientHandler)
        XCTAssertThrowsError(try clientChannel.throwIfErrorCaught()) { error in
            XCTAssertTrue(error is NIOSSLCloseTimedOutError, "Unexpected error: \(error)")
        }

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertTrue(unwrapped)
    }

    func testSuccessfulUnwrapCancelsTimeout() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var serverClosed = false
        var unwrapped = false

        defer {
            XCTAssertNoThrow(try serverChannel.finish(acceptAlreadyClosed: false))
            XCTAssertNoThrow(try clientChannel.finish(acceptAlreadyClosed: true))
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let serverHandler = try assertNoThrowWithValue(NIOSSLServerHandler(context: context))
        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(serverHandler))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the channels.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }
        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the server connection.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenSuccess { result in
            unwrapped = true
        }
        serverHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)

        // Now interact in memory.
        XCTAssertNoThrow(
            try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel, runLoops: false)
        )

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertTrue(unwrapped)
        serverChannel.pipeline.syncOperations.assertDoesNotContain(handler: serverHandler)

        // Now advance time by 5 seconds and confirm that the server doesn't get closed.
        serverChannel.embeddedEventLoop.advanceTime(by: .seconds(5))
        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertTrue(unwrapped)
        serverChannel.pipeline.syncOperations.assertDoesNotContain(handler: serverHandler)
    }

    func testUnwrappingAndClosingShareATimeout() throws {
        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var clientClosed = false
        var serverClosed = false
        var unwrapped = false
        var closed = false

        defer {
            XCTAssertNoThrow(try serverChannel.finish(acceptAlreadyClosed: true))
            XCTAssertNoThrow(try clientChannel.finish(acceptAlreadyClosed: false))
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())

        let serverHandler = try assertNoThrowWithValue(NIOSSLServerHandler(context: context))
        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(serverHandler))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        // Mark the closure of the channels.
        clientChannel.closeFuture.assumeIsolated().whenComplete { _ in
            clientClosed = true
        }
        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Connect. This should lead to a completed handshake.
        XCTAssertNoThrow(try connectInMemory(client: clientChannel, server: serverChannel))
        XCTAssertTrue(handshakeHandler.handshakeSucceeded)

        // Let's unwrap the server connection. We are not going to interact in memory, because we want to simulate a
        // timeout.
        let stopPromise: EventLoopPromise<Void> = clientChannel.eventLoop.makePromise()
        stopPromise.futureResult.assumeIsolated().whenComplete { result in
            unwrapped = true

            switch result {
            case .success:
                XCTFail("Shutdown succeeded unexpectedly")
            case .failure(let err):
                XCTAssertTrue(err is NIOSSLCloseTimedOutError, "Unexpected error: \(err)")
            }
        }
        serverHandler.stopTLS(promise: stopPromise)

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)

        // Advance time by 3 seconds. This should not fire the timeout.
        serverChannel.embeddedEventLoop.advanceTime(by: .seconds(3))
        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)
        serverChannel.pipeline.syncOperations.assertContains(handler: serverHandler)

        // Now we close. This will report success.
        serverChannel.close().assumeIsolated().whenSuccess { result in
            closed = true
        }

        XCTAssertFalse(clientClosed)
        XCTAssertFalse(serverClosed)
        XCTAssertFalse(unwrapped)
        XCTAssertFalse(closed)
        serverChannel.pipeline.syncOperations.assertContains(handler: serverHandler)

        // Now we advance two more seconds. This closes the connection. All the promises succeed.
        serverChannel.embeddedEventLoop.advanceTime(by: .seconds(2))
        XCTAssertFalse(clientClosed)
        XCTAssertTrue(serverClosed)
        XCTAssertTrue(unwrapped)
        XCTAssertTrue(closed)
        serverChannel.pipeline.syncOperations.assertDoesNotContain(handler: serverHandler)

        // Now we do the same for the client to get it out of the pipeline too. Naturally, it'll time out.
        clientHandler.stopTLS(promise: nil)
        clientChannel.embeddedEventLoop.advanceTime(by: .seconds(5))
        clientChannel.pipeline.syncOperations.assertDoesNotContain(handler: clientHandler)
        XCTAssertThrowsError(try clientChannel.throwIfErrorCaught()) { error in
            XCTAssertTrue(error is NIOSSLCloseTimedOutError, "Unexpected error: \(error)")
        }

        XCTAssertFalse(clientClosed)
        XCTAssertTrue(serverClosed)
        XCTAssertTrue(unwrapped)
    }

    func testChannelInactiveDuringHandshake() throws {

        let serverChannel = EmbeddedChannel()
        let clientChannel = EmbeddedChannel()

        var serverClosed = false
        var serverUnwrapped = false
        defer {
            // The errors here are expected
            XCTAssertThrowsError(try serverChannel.finish())
            XCTAssertThrowsError(try clientChannel.finish())
        }

        let context = try assertNoThrowWithValue(configuredSSLContext())
        let serverHandler = try assertNoThrowWithValue(NIOSSLServerHandler(context: context))
        let clientHandler = try assertNoThrowWithValue(NIOSSLClientHandler(context: context, serverHostname: nil))
        XCTAssertNoThrow(try serverChannel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context)))
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(clientHandler))
        let handshakeHandler = HandshakeCompletedHandler()
        XCTAssertNoThrow(try clientChannel.pipeline.syncOperations.addHandler(handshakeHandler))

        serverChannel.closeFuture.assumeIsolated().whenComplete { _ in
            serverClosed = true
        }

        // Place the guts of connectInMemory here to abruptly alter the handshake process
        let addr = try assertNoThrowWithValue(SocketAddress(unixDomainSocketPath: "/tmp/whatever2"))
        let _ = clientChannel.connect(to: addr)

        XCTAssertFalse(serverClosed)

        serverChannel.pipeline.fireChannelActive()
        clientChannel.pipeline.fireChannelActive()
        // doHandshakeStep process should start here out in NIOSSLHandler before fireChannelInactive
        serverChannel.pipeline.fireChannelInactive()
        clientChannel.pipeline.fireChannelInactive()

        // Need to test this error as a BoringSSLError because that means success instead of an uncleanShutdown
        do {
            try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel)
        } catch {
            switch error as? NIOSSLError {
            case .some(.handshakeFailed(let innerError)):
                // Expected to fall into .handshakeFailed with .eofDuringHandshake
                XCTAssertEqual(innerError, .sslError([.eofDuringHandshake]))
            default:
                XCTFail("Unexpected error: \(error)")
            }
        }
        clientHandler.stopTLS(promise: nil)

        // Go through the process of closing and verifying the close on the server side.
        XCTAssertFalse(serverUnwrapped)

        let serverStopPromise: EventLoopPromise<Void> = serverChannel.eventLoop.makePromise()
        serverStopPromise.futureResult.assumeIsolated().whenComplete { _ in
            serverUnwrapped = true
        }
        serverHandler.stopTLS(promise: serverStopPromise)
        XCTAssertNoThrow(try interactInMemory(clientChannel: clientChannel, serverChannel: serverChannel))

        (serverChannel.eventLoop as! EmbeddedEventLoop).run()

        XCTAssertTrue(serverClosed)
        XCTAssertTrue(serverUnwrapped)
    }
}
