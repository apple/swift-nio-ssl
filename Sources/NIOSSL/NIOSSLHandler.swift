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
import NIOCore
import NIOTLS

/// The base class for all NIOSSL handlers.
///
/// This class cannot actually be instantiated by users directly: instead, users must select
/// which mode they would like their handler to operate in, client or server.
///
/// This class exists to deal with the reality that for almost the entirety of the lifetime
/// of a TLS connection there is no meaningful distinction between a server and a client.
/// For this reason almost the entirety of the implementation for the channel and server
/// handlers in NIOSSL is shared, in the form of this parent class.
public class NIOSSLHandler: ChannelInboundHandler, ChannelOutboundHandler, RemovableChannelHandler {
    /// The default maximum write size. We cannot pass writes larger than this size to
    /// BoringSSL.
    ///
    /// We have this default here instead of hardcoded into the software for testing purposes.
    internal static let defaultMaxWriteSize = Int(CInt.max)

    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer

    private enum ConnectionState {
        case idle
        case handshaking
        case additionalVerification
        case active
        case unwrapping(Scheduled<Void>)
        case closing(Scheduled<Void>)
        case unwrapped
        case inputClosed
        case outputClosed
        case closed
    }

    private var state: ConnectionState = .idle
    private var connection: SSLConnection
    private var plaintextReadBuffer: ByteBuffer?
    private var bufferedActions: MarkedCircularBuffer<BufferedAction>
    private var closeOutputPromise: EventLoopPromise<Void>?
    private var closePromise: EventLoopPromise<Void>?
    private var shutdownPromise: EventLoopPromise<Void>?
    private var didDeliverData: Bool = false
    private var storedContext: ChannelHandlerContext? = nil
    private var shutdownTimeout: TimeAmount
    private let additionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?
    private let maxWriteSize: Int
    private var configuration: Configuration

    internal var channel: Channel? {
        self.storedContext?.channel
    }

    internal init(
        connection: SSLConnection,
        shutdownTimeout: TimeAmount,
        additionalPeerCertificateVerificationCallback: _NIOAdditionalPeerCertificateVerificationCallback?,
        maxWriteSize: Int,
        configuration: Configuration
    ) {
        let tlsConfiguration = connection.parentContext.configuration
        precondition(
            additionalPeerCertificateVerificationCallback == nil || tlsConfiguration.certificateVerification != .none,
            "TLSConfiguration.certificateVerification must be either set to .optionalVerification, .noHostnameVerification, or .fullVerification if additionalPeerCertificateVerificationCallback is specified"
        )
        self.connection = connection
        // 96 brings the total size of the buffer to just shy of one page
        self.bufferedActions = MarkedCircularBuffer(initialCapacity: 96)
        self.shutdownTimeout = shutdownTimeout
        self.additionalPeerCertificateVerificationCallback = additionalPeerCertificateVerificationCallback
        self.maxWriteSize = maxWriteSize
        self.configuration = configuration
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        self.storedContext = context
        self.connection.setAllocator(context.channel.allocator, maximumPreservedOutboundBufferCapacity: .max)
        self.connection.parentHandler = self
        self.connection.eventLoop = context.eventLoop

        self.plaintextReadBuffer = context.channel.allocator.buffer(capacity: SSL_MAX_RECORD_SIZE)
        // If this channel is already active, immediately begin handshaking.
        if context.channel.isActive {
            doHandshakeStep(context: context)
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        /// Get the connection to drop any state it might have. This state can cause reference cycles,
        /// so we need to break those when we know it's safe to do so. This is a good safe point, as no
        /// further I/O can possibly occur.
        self.connection.close()

        // We now want to drop the stored context.
        self.storedContext = nil
    }

    public func channelActive(context: ChannelHandlerContext) {
        // We fire this a bit early, entirely on purpose. This is because
        // in doHandshakeStep we may end up closing the channel again, and
        // if we do we want to make sure that the channelInactive message received
        // by later channel handlers makes sense.
        context.fireChannelActive()
        doHandshakeStep(context: context)
    }

    public func channelInactive(context: ChannelHandlerContext) {
        // This fires when the TCP connection goes away. Whatever happens, we end up in the closed
        // state here. This function calls out to a lot of user code, so we need to make sure we're
        // keeping track of the state we're in properly before we do anything else.
        let oldState = state
        state = .closed
        let channelError: NIOSSLError

        switch oldState {
        case .closed, .idle:
            // Nothing to do, but discard any buffered actions we still have.
            discardBufferedActions(reason: ChannelError.ioOnClosedChannel)
            // Return early
            context.fireChannelInactive()
            return
        case .handshaking:
            // In this case the channel is going through the doHandshake steps and
            // a channelInactive is fired taking down the connection.
            // This case propogates a .handshakeFailed instead of an .uncleanShutdown.
            // We use a synthetic error here as the error stack will be empty, and we should try to
            // provide some diagnostic help.
            channelError = NIOSSLError.handshakeFailed(.sslError([.eofDuringHandshake]))
        case .additionalVerification:
            // In this case the channel is going through the doHandshake steps and
            // a channelInactive is fired taking down the connection.
            // This case propogates a .handshakeFailed instead of an .uncleanShutdown.
            // We use a synthetic error here as the error stack will be empty, and we should try to
            // provide some diagnostic help.
            channelError = NIOSSLError.handshakeFailed(.sslError([.eofDuringAdditionalCertficiateChainValidation]))
        default:
            // This is a ragged EOF: we weren't sent a CLOSE_NOTIFY. We want to send a user
            // event to notify about this before we propagate channelInactive. We also want to fail all
            // these writes.
            channelError = NIOSSLError.uncleanShutdown
        }
        let shutdownPromise = self.shutdownPromise
        self.shutdownPromise = nil
        let closePromise = self.closePromise
        self.closePromise = nil

        shutdownPromise?.fail(channelError)
        closePromise?.fail(channelError)
        context.fireErrorCaught(channelError)
        discardBufferedActions(reason: channelError)

        context.fireChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let binaryData = unwrapInboundIn(data)

        // The logic: feed the buffers, then take an action based on state.
        connection.consumeDataFromNetwork(binaryData)

        switch state {
        case .handshaking:
            doHandshakeStep(context: context)
        case .active, .outputClosed:
            doDecodeData(context: context)
            doUnbufferActions(context: context)
        case .closing:
            // Handle both natural close events and close events where data is still in
            // flight.  Sending through doDecodeData will handle both conditions.
            doDecodeData(context: context)
        case .unwrapping:
            self.doShutdownStep(context: context)
        default:
            context.fireErrorCaught(NIOSSLError.readInInvalidTLSState)
            channelClose(context: context, reason: NIOSSLError.readInInvalidTLSState)
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        guard let receiveBuffer = self.plaintextReadBuffer else {
            preconditionFailure("channelReadComplete called before handlerAdded")
        }

        self.doFlushReadData(context: context, receiveBuffer: receiveBuffer, readOnEmptyBuffer: true)
        self.writeDataToNetwork(context: context, promise: nil)
    }

    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case ChannelEvent.inputClosed:
            userInboundInputClosedTriggered(context: context)
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    private func userInboundInputClosedTriggered(context: ChannelHandlerContext) {
        let channelError: NIOSSLError
        switch self.state {
        case .inputClosed:
            return
        case .closed, .idle:
            context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
            return
        case .handshaking:
            // In this case the channel is going through the doHandshake steps and
            // a channelInactive is fired taking down the connection.
            // This case propogates a .handshakeFailed instead of an .uncleanShutdown.
            // We use a synthetic error here as the error stack will be empty, and we should try to
            // provide some diagnostic help.
            channelError = NIOSSLError.handshakeFailed(.sslError([.eofDuringHandshake]))
        case .additionalVerification:
            // In this case the channel is going through the doHandshake steps and
            // a channelInactive is fired taking down the connection.
            // This case propogates a .handshakeFailed instead of an .uncleanShutdown.
            // We use a synthetic error here as the error stack will be empty, and we should try to
            // provide some diagnostic help.
            channelError = NIOSSLError.handshakeFailed(.sslError([.eofDuringAdditionalCertficiateChainValidation]))
        default:
            // This is a ragged EOF: we weren't sent a CLOSE_NOTIFY. We want to send a user
            // event to notify about this before we propagate channelInactive. We also want to fail all
            // these writes.
            channelError = NIOSSLError.uncleanShutdown
        }
        context.fireErrorCaught(channelError)
        context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        bufferWrite(data: unwrapOutboundIn(data), promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        switch self.state {
        case .idle, .handshaking, .additionalVerification:
            // we should not flush immediately as we have not completed the handshake and instead buffer the flush
            self.bufferFlush()
        case .active, .unwrapping, .closing, .unwrapped, .inputClosed, .outputClosed, .closed:
            self.bufferFlush()
            self.doUnbufferActions(context: context)
        }
    }

    public func close(context: ChannelHandlerContext, mode: CloseMode, promise: EventLoopPromise<Void>?) {
        switch mode {
        case .output:
            self.closeOutput(context: context, promise: promise)
        case .all:
            self.closeAll(context: context, promise: promise)
        case .input:
            promise?.fail(ChannelError.operationUnsupported)
        }
    }

    private func closeOutput(context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) {
        switch state {
        case .closing:
            // We're in the process of TLS shutdown, which has a higher priority.
            // Therefore we skip the output closing procedure and cascade the result
            // of the TLS shutdown request to this new one.
            if let promise = promise, let closePromise = self.closePromise {
                closePromise.futureResult.cascade(to: promise)
            } else if let promise = promise {
                self.closePromise = promise
            }
        case .idle, .outputClosed, .closed, .unwrapping, .unwrapped:
            // For idle, outputClosed, closed, unwrapping, and unwrapped connections we immediately pass this on to the next
            // channel handler.
            context.close(mode: .output, promise: promise)
        case .handshaking, .additionalVerification:
            // We are still in the process of handshaking / doing additional verification.
            // This means our outstanding writes will not get flushed until we have reached the active state.
            // Therefore we buffer the .closeOuput action and wait for it to be executed after all our
            // outstanding writes have been flushed in the active state.
            self.bufferedActions.append(.closeOutput)
            self.flush(context: context)
            self.closeOutputPromise = promise
        case .inputClosed:
            // Input is already closed and we want to close our output.
            // This escalates to a full closure.
            self.close(context: context, mode: .all, promise: promise)
        case .active:
            // We need to begin processing closeOutput now.
            // We can't fire the promise for a while though.
            self.state = .outputClosed
            self.closeOutputPromise = promise
            self.flush(context: context)
            self.doShutdownStep(context: context)
        }
    }

    private func closeAll(context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) {
        switch state {
        case .closing:
            // We're in the process of TLS shutdown, so let's let that happen. However,
            // we want to cascade the result of the first request into this new one.
            if let promise = promise, let closePromise = self.closePromise {
                closePromise.futureResult.cascade(to: promise)
            } else if let promise = promise {
                self.closePromise = promise
            }
        case .unwrapping(let scheduledShutdown):
            // We've been asked to close the connection, but we were currently unwrapping.
            // We don't have to send any CLOSE_NOTIFY, but we now need to upgrade ourselves:
            // closing is a more extreme activity than unwrapping.
            self.state = .closing(scheduledShutdown)
            if let promise = promise, let closePromise = self.closePromise {
                closePromise.futureResult.cascade(to: promise)
            } else if let promise = promise {
                self.closePromise = promise
            }
        case .idle:
            state = .closed
            fallthrough
        case .closed, .unwrapped:
            // For idle, closed, and unwrapped connections we immediately pass this on to the next
            // channel handler.
            context.close(promise: promise)
        case .active, .inputClosed, .outputClosed, .handshaking, .additionalVerification:
            // We need to begin processing shutdown now. We can't fire the promise for a
            // while though.
            self.state = .closing(self.scheduleTimedOutShutdown(context: context))
            closePromise = promise
            doShutdownStep(context: context)
        }
    }

    /// Attempt to perform another stage of the TLS handshake.
    ///
    /// A TLS connection has a multi-step handshake that requires at least two messages sent by each
    /// peer. As a result, a handshake will never complete in a single call to BoringSSL. This method
    /// will call `doHandshake`, and will then attempt to write whatever data this generated to the
    /// network. If we are waiting on data from the remote peer, this method will do nothing.
    ///
    /// This method must not be called once the connection is established.
    private func doHandshakeStep(context: ChannelHandlerContext) {
        switch self.state {
        case .unwrapped, .inputClosed, .outputClosed, .closed:
            // We shouldn't be handshaking in any of these state.
            return
        case .idle, .handshaking, .additionalVerification, .active, .closing, .unwrapping:
            ()
        }

        let result = self.connection.doHandshake()

        switch result {
        case .incomplete:
            state = .handshaking
            writeDataToNetwork(context: context, promise: nil)
        case .complete:
            do {
                try validateHostname(context: context)
            } catch {
                // This counts as a failure.
                context.fireErrorCaught(error)
                channelClose(context: context, reason: error)
                return
            }

            if let additionalPeerCertificateVerificationCallback = self.additionalPeerCertificateVerificationCallback {
                state = .additionalVerification
                guard let peerCertificate = connection.getPeerCertificate() else {
                    preconditionFailure(
                        """
                            Couldn't get peer certificate after chain verification was successful.
                            This should be impossible as we have a precondition during creation of this handler that requires certificate verification.
                            Please file an issue.
                        """
                    )
                }
                additionalPeerCertificateVerificationCallback(peerCertificate, context.channel)
                    .hop(to: context.eventLoop)
                    .assumeIsolated()
                    .whenComplete { result in
                        self.completedAdditionalPeerCertificateVerification(result: result)
                    }
                return
            }

            state = .active
            completeHandshake(context: context)
        case .failed(let err):
            writeDataToNetwork(context: context, promise: nil)

            // If there's a failed private key operation, we fire both errors.
            if case .failure(let privateKeyError) = self.connection.customPrivateKeyResult {
                context.fireErrorCaught(privateKeyError)
            }

            // If there's a failed custom context operation, we fire both errors.
            if let customContextError = self.connection.customContextManager?.loadContextError {
                context.fireErrorCaught(customContextError)
            }

            context.fireErrorCaught(NIOSSLError.handshakeFailed(err))
            channelClose(context: context, reason: NIOSSLError.handshakeFailed(err))
        }
    }

    private func completeHandshake(context: ChannelHandlerContext) {
        writeDataToNetwork(context: context, promise: nil)

        // TODO(cory): This event should probably fire out of the BoringSSL info callback.
        let negotiatedProtocol = connection.getAlpnProtocol()
        context.fireUserInboundEventTriggered(TLSUserEvent.handshakeCompleted(negotiatedProtocol: negotiatedProtocol))

        // We need to unbuffer any pending writes and reads. We will have pending writes if the user attempted to
        // write before we completed the handshake. We may also have pending reads if the user sent data immediately
        // after their FINISHED record. We decode the reads first, as those reads may trigger writes.
        self.doDecodeData(context: context)
        if let receiveBuffer = self.plaintextReadBuffer {
            self.doFlushReadData(context: context, receiveBuffer: receiveBuffer, readOnEmptyBuffer: false)
        }
        self.doUnbufferActions(context: context)
    }

    private func completedAdditionalPeerCertificateVerification(result: Result<Void, Error>) {
        guard let context = self.storedContext else {
            // `self` may already be removed from the channel pipeline
            return
        }
        context.eventLoop.preconditionInEventLoop()

        switch self.state {
        case .idle, .handshaking, .active, .inputClosed, .outputClosed:
            preconditionFailure("invalid state \(self.state)")
        case .additionalVerification:
            switch result {
            case .failure(let error):
                // This counts as a failure.
                context.fireErrorCaught(error)
                channelClose(context: context, reason: error)
            case .success:
                state = .active
                completeHandshake(context: context)
            }
        case .unwrapping, .closing, .unwrapped, .closed:
            break
        // we are already about to close, we can safely ignore this event
        }
    }

    /// Attempt to perform a stage of orderly TLS shutdown.
    ///
    /// Orderly TLS shutdown requires each peer to send a TLS CloseNotify message.
    /// This message is a signal that the data being sent has been completely sent,
    /// without truncation. Where possible we attempt to perform an orderly shutdown,
    /// and so we will send a CloseNotify. We also try to wait for the remote peer to
    /// send a CloseNotify in response. This means we may call this multiple times,
    /// potentially writing our own CloseNotify each time.
    ///
    /// Once `state` has transitioned to `.closed`, further calls to this method will
    /// do nothing.
    private func doShutdownStep(context: ChannelHandlerContext) {
        if case .closed = self.state {
            return
        }

        let result = connection.doShutdown()

        var uncleanScheduledShutdown: Scheduled<Void>?
        let targetCompleteState: ConnectionState
        switch self.state {
        case .outputClosed:
            targetCompleteState = .outputClosed
        case .closing(let scheduledShutdown):
            uncleanScheduledShutdown = scheduledShutdown
            targetCompleteState = .closed
        case .unwrapping(let scheduledShutdown):
            uncleanScheduledShutdown = scheduledShutdown
            targetCompleteState = .unwrapped
        default:
            preconditionFailure("Shutting down in a non-shutting-down state")
        }

        switch result {
        case .incomplete:
            writeDataToNetwork(context: context, promise: nil)

            if case .outputClosed = targetCompleteState {
                self.state = targetCompleteState
                self.channelCloseOutput(context: context)
            }
        case .complete:
            uncleanScheduledShutdown?.cancel()
            self.state = targetCompleteState
            writeDataToNetwork(context: context, promise: nil)

            // TODO(cory): This should probably fire out of the BoringSSL info callback.
            context.fireUserInboundEventTriggered(TLSUserEvent.shutdownCompleted)

            switch targetCompleteState {
            case .outputClosed:
                /// No full channel close here. We expect users to invoke a full close even when the
                /// connection has been half-closed in one direction.
                /// Note: half closure for input and output results in a full close.
                self.channelCloseOutput(context: context)
            case .closed:
                self.channelClose(context: context, reason: NIOTLSUnwrappingError.closeRequestedDuringUnwrap)
            case .unwrapped:
                self.channelUnwrap(context: context)
            default:
                preconditionFailure("Cannot be in \(targetCompleteState) at this code point")
            }
        case .failed(let err):
            uncleanScheduledShutdown?.cancel()
            // TODO(cory): This should probably fire out of the BoringSSL info callback.
            context.fireErrorCaught(NIOSSLError.shutdownFailed(err))
            channelClose(context: context, reason: NIOSSLError.shutdownFailed(err))
        }
    }

    /// Creates a scheduled task to perform an unclean shutdown in event of a clean shutdown timing
    /// out. This task should be cancelled if the shutdown does not time out.
    private func scheduleTimedOutShutdown(context: ChannelHandlerContext) -> Scheduled<Void> {
        context.eventLoop.assumeIsolated().scheduleTask(in: self.shutdownTimeout) {
            switch self.state {
            case .inputClosed, .outputClosed, .idle, .handshaking, .additionalVerification, .active:
                preconditionFailure("Cannot schedule timed out shutdown on non-shutting down handler")

            case .closed, .unwrapped:
                // This means we raced with the shutdown completing. We just let this one go: do nothing.
                return

            case .closing:
                // We're closing, the only thing we do here is exit.
                self.state = .closed
                self.channelClose(context: context, reason: NIOSSLCloseTimedOutError())

            case .unwrapping:
                // The user only wants us to error and unwrap, not to close.
                self.state = .unwrapped
                self.channelUnwrap(context: context, failedWithError: NIOSSLCloseTimedOutError())
            }
        }
    }

    /// Loops over the `SSL` object, decoding encrypted application data until there is
    /// no more available.
    private func doDecodeData(context: ChannelHandlerContext) {
        guard var receiveBuffer = self.plaintextReadBuffer else {
            preconditionFailure("didDecodeData called without handlerAdded firing.")
        }

        // We nil the read buffer here. This is done on purpose: we do it to ensure
        // that we don't have two references to the buffer, otherwise readDataFromNetwork
        // will trigger a CoW every time. We need to put this back on every exit from this
        // function, or before any call-out, to avoid re-entrancy issues. We validate the
        // requirement for this being non-nil on exit at the very least.
        self.plaintextReadBuffer = nil
        defer {
            assert(self.plaintextReadBuffer != nil)
        }

        readLoop: while true {
            let result = connection.readDataFromNetwork(outputBuffer: &receiveBuffer)

            switch result {
            case .complete:
                // Good read. Keep going
                continue readLoop

            case .incomplete:
                self.plaintextReadBuffer = receiveBuffer
                break readLoop

            case .failed(BoringSSLError.zeroReturn):
                let allowRemoteHalfClosure = self.getAllowRemoteHalfClosureFromChannel(context: context)

                switch self.state {
                case .idle, .handshaking, .additionalVerification:
                    preconditionFailure("Should not get zeroReturn in \(self.state)")
                case .closed, .unwrapped:
                    // This is an unexpected place to be, but it's not totally impossible. Assume this
                    // is the result of a wonky I/O pattern and just ignore it.
                    self.plaintextReadBuffer = receiveBuffer
                    break readLoop
                case .active, .outputClosed:
                    if allowRemoteHalfClosure == false {
                        self.state = .closing(self.scheduleTimedOutShutdown(context: context))
                    }
                case .unwrapping, .closing, .inputClosed:
                    break
                }

                // This is a clean EOF: we can just start doing our own clean shutdown.
                self.doFlushReadData(context: context, receiveBuffer: receiveBuffer, readOnEmptyBuffer: false)

                if allowRemoteHalfClosure {
                    switch self.state {
                    case .active, .unwrapping:
                        self.state = .inputClosed
                    case .outputClosed:
                        // Wanting to close input when output is already closed,
                        // escalate to full shutdown
                        self.close(context: context, mode: .all, promise: nil)
                    default:
                        break
                    }
                    context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
                } else {
                    self.doShutdownStep(context: context)
                }

                writeDataToNetwork(context: context, promise: nil)
                break readLoop

            case .failed(let err):
                self.state = .closed
                self.plaintextReadBuffer = receiveBuffer
                context.fireErrorCaught(err)
                channelClose(context: context, reason: err)
                break readLoop
            }
        }
    }

    /// Checks if the `allowRemoteHalfClosure` channel option is set.
    private func getAllowRemoteHalfClosureFromChannel(context: ChannelHandlerContext) -> Bool {
        var halfClosureAllowed = false
        if let syncOptions = context.channel.syncOptions {
            if let result = try? syncOptions.getOption(ChannelOptions.allowRemoteHalfClosure) {
                halfClosureAllowed = result
            }
        }
        return halfClosureAllowed
    }

    /// Flushes any pending read plaintext. This is called whenever we hit a flush
    /// point for reads: either channelReadComplete, or we receive a CLOSE_NOTIFY.
    ///
    /// This function will always set the empty buffer back to be the plaintext read buffer.
    /// Do not do this in your own code.
    private func doFlushReadData(context: ChannelHandlerContext, receiveBuffer: ByteBuffer, readOnEmptyBuffer: Bool) {
        defer {
            // All exits from this function must restore the plaintext read buffer.
            assert(self.plaintextReadBuffer != nil)
        }

        // We only want to fire channelReadComplete in a situation where we have actually sent the user some data, otherwise
        // we'll be confusing the hell out of them.
        if receiveBuffer.writerIndex > receiveBuffer.readerIndex {
            // We need to be very careful here: we must not call out before we fix up our local view of this buffer. In this
            // case, we're going to set the indices back to where they were. In this case we are deliberately *not* calling
            // clear(), as we don't want to trigger a CoW for our own local refs.
            var ourNewBuffer = receiveBuffer
            ourNewBuffer.moveReaderIndex(to: 0)
            ourNewBuffer.moveWriterIndex(to: 0)
            self.plaintextReadBuffer = ourNewBuffer

            // Ok, we can now pass the receive buffer on and fire channelReadComplete.
            context.fireChannelRead(self.wrapInboundOut(receiveBuffer))
            context.fireChannelReadComplete()
        } else if readOnEmptyBuffer {
            // We didn't deliver data, but the channel is still active. If this channel has got
            // autoread turned off then we should call read again, because otherwise the user
            // will never see any result from their read call.
            //
            // In the unlikely event we couldn't get the answer, we assume auto-read is on.
            self.plaintextReadBuffer = receiveBuffer

            do {
                let autoRead = try context.channel.syncOptions?.getOption(ChannelOptions.autoRead) ?? true
                if !autoRead {
                    context.read()
                }
            } catch {
                context.fireErrorCaught(error)
            }
        } else {
            // Regardless of what happens here, we need to put the plaintext read buffer back. Very important.
            self.plaintextReadBuffer = receiveBuffer
        }
    }

    /// Encrypts application data and writes it to the channel.
    ///
    /// This method always flushes. For this reason, it should only ever be called when a flush
    /// is intended.
    private func writeDataToNetwork(context: ChannelHandlerContext, promise: EventLoopPromise<Void>?) {
        // There may be no data to write, in which case we can just exit early.
        guard let dataToWrite = connection.getDataForNetwork() else {
            if let promise = promise {
                // If we have a promise, we need to enforce ordering so we issue a zero-length write that
                // the event loop will have to handle.
                let buffer = context.channel.allocator.buffer(capacity: 0)
                context.writeAndFlush(wrapInboundOut(buffer), promise: promise)
            }
            return
        }

        context.writeAndFlush(self.wrapInboundOut(dataToWrite), promise: promise)
    }

    /// Simply calls `ChannelHandlerContext.close(mode: .output)` with
    /// any promise we may have already been given.
    private func channelCloseOutput(context: ChannelHandlerContext) {
        let closeOutputPromise = self.closeOutputPromise
        self.closeOutputPromise = nil
        context.close(mode: .output, promise: closeOutputPromise)
    }

    /// Close the underlying channel.
    ///
    /// This method does not perform any kind of I/O. Instead, it simply calls ChannelHandlerContext.close with
    /// any promise we may have already been given. It also transitions our state into closed. This should only be
    /// used to clean up after an error, or to perform the final call to close after a clean shutdown attempt.
    private func channelClose(context: ChannelHandlerContext, reason: Error) {
        state = .closed

        let shutdownPromise = self.shutdownPromise
        self.shutdownPromise = nil

        let closePromise = self.closePromise
        self.closePromise = nil

        shutdownPromise?.fail(reason)
        context.close(promise: closePromise)
    }

    private func channelUnwrap(context: ChannelHandlerContext, failedWithError error: Error? = nil) {
        assert(self.closePromise == nil)
        self.state = .unwrapped

        let shutdownPromise = self.shutdownPromise
        self.shutdownPromise = nil

        // We create a promise here to make sure we operate in the special magic state
        // where we are not in the pipeline any more, but we still have a valid context.
        let removalPromise: EventLoopPromise<Void> = context.eventLoop.makePromise()
        let removalFuture = removalPromise.futureResult.assumeIsolated().map {
            // Now drop all actions.
            self.discardBufferedActions(reason: NIOTLSUnwrappingError.unflushedWriteOnUnwrap)

            if let unconsumedData = self.connection.extractUnconsumedData() {
                context.fireChannelRead(self.wrapInboundOut(unconsumedData))
            }

            if let error = error {
                context.fireErrorCaught(error)
            }
        }

        if let promise = shutdownPromise {
            removalFuture.whenComplete { result in
                switch (result, error) {
                case (.success, .none):
                    promise.succeed(())
                case (.success, .some(let error)):
                    promise.fail(error)
                case (.failure(let failure), _):
                    promise.fail(failure)
                }
            }
            removalFuture.nonisolated().cascade(to: promise)
        }

        // Ok, we've unwrapped. Let's get out of the channel.
        context.channel.pipeline.syncOperations.removeHandler(context: context, promise: removalPromise)
    }

    /// Validates the hostname from the certificate against the hostname provided by
    /// the user, assuming one has been provided at all.
    private func validateHostname(context: ChannelHandlerContext) throws {
        guard connection.validateHostnames else {
            return
        }

        // If there is no remote address, something weird is happening here. We can't
        // validate a certificate without it, so bail.
        guard let ipAddress = context.channel.remoteAddress else {
            throw NIOSSLError.cannotFindPeerIP
        }

        try connection.validateHostname(address: ipAddress)
    }
}

@available(*, unavailable)
extension NIOSSLHandler: Sendable {}

extension NIOSSLHandler {
    /// Variable that can be queried during the connection lifecycle to grab the ``TLSVersion`` used on this connection.
    ///
    /// This variable **is not thread-safe**: you **must** call it from the correct event
    /// loop thread.
    public var tlsVersion: TLSVersion? {
        self.connection.getTLSVersionForConnection()
    }

    /// Return a NIOSSLCertificate from the verified peer after handshake has completed.
    ///
    /// Similar to getTlsVersionForConnection this **is not thread safe**.
    public var peerCertificate: NIOSSLCertificate? {
        self.connection.getPeerCertificate()
    }

    /// Return the *validated* certificate chain from the verified peer after handshake has completed.
    ///
    /// This property will only contain a value if the handler was initialized with a custom certificate verification
    /// callback (``NIOSSLCustomVerificationCallbackWithMetadata``) *and* if the promise in the callback was
    /// successfully completed with ``NIOSSLVerificationResultWithMetadata/certificateVerified(_:)`` (containing a
    /// ``VerificationMetadata`` instance with a ``ValidatedCertificateChain``). If either of these conditions are not
    /// met, this property will be `nil`.
    ///
    /// To create a `NIOSSLClientHandler` handler with a custom verification callback that can return the certificate
    /// chain, use:
    /// - ``NIOSSLClientHandler/init(context:serverHostname:customVerificationCallbackWithMetadata:)`` or
    /// - ``NIOSSLClientHandler/init(context:serverHostname:configuration:customVerificationCallbackWithMetadata:)``
    /// For `NIOSSLServerHandler`, use:
    /// - ``NIOSSLServerHandler/init(context:customVerificationCallbackWithMetadata:)`` or
    /// - ``NIOSSLServerHandler/init(context:configuration:customVerificationCallbackWithMetadata:)``
    ///
    public var peerValidatedCertificateChain: ValidatedCertificateChain? {
        self.connection.customVerificationManager?.verificationMetadata?.validatedCertificateChain
    }
}

extension Channel {
    ///  API to extract the ``TLSVersion`` from off the `Channel`.
    public func nioSSL_tlsVersion() -> EventLoopFuture<TLSVersion?> {
        self.pipeline.handler(type: NIOSSLHandler.self).map {
            $0.tlsVersion
        }
    }

    /// API to retrieve the verified NIOSSLCertificate of the peer off the 'Channel'
    public func nioSSL_peerCertificate() -> EventLoopFuture<NIOSSLCertificate?> {
        self.pipeline.handler(type: NIOSSLHandler.self).map {
            $0.peerCertificate
        }
    }

    /// API to retrieve the *validated* certificate chain of the peer. See ``NIOSSLHandler/peerValidatedCertificateChain``.
    public func nioSSL_peerValidatedCertificateChain() -> EventLoopFuture<ValidatedCertificateChain?> {
        self.pipeline.handler(type: NIOSSLHandler.self).map {
            $0.peerValidatedCertificateChain
        }
    }
}

extension ChannelPipeline.SynchronousOperations {
    /// API to query the ``TLSVersion`` directly from the `ChannelPipeline`.
    public func nioSSL_tlsVersion() throws -> TLSVersion? {
        let handler = try self.handler(type: NIOSSLHandler.self)
        return handler.tlsVersion
    }

    /// API to retrieve the verified NIOSSLCertificate of the peer directly from the 'ChannelPipeline'
    public func nioSSL_peerCertificate() throws -> NIOSSLCertificate? {
        let handler = try self.handler(type: NIOSSLHandler.self)
        return handler.peerCertificate
    }

    /// API to retrieve the *validated* certificate chain of the peer. See ``NIOSSLHandler/peerValidatedCertificateChain``.
    public func nioSSL_peerValidatedCertificateChain() throws -> ValidatedCertificateChain? {
        let handler = try self.handler(type: NIOSSLHandler.self)
        return handler.peerValidatedCertificateChain
    }
}

// MARK:- Extension APIs for users.
extension NIOSSLHandler {
    /// Called to instruct this handler to perform an orderly TLS shutdown and then remove itself
    /// from the pipeline. This will leave the connection established, but remove the TLS wrapper
    /// from it.
    ///
    /// This will send a `CLOSE_NOTIFY` and wait for the corresponding `CLOSE_NOTIFY`. When that next
    /// `CLOSE_NOTIFY` is received, this handler will pass on all pending writes and remove itself
    /// from the channel pipeline. If the shutdown times out then an error will fire down the
    /// pipeline, this handler will remove itself from the pipeline, but the channel will not be
    /// automatically closed.
    ///
    /// This function **is not thread-safe**: you **must** call it from the correct event
    /// loop thread.
    ///
    /// - parameters:
    ///     - promise: An `EventLoopPromise` that will be completed when the unwrapping has
    ///         completed.
    public func stopTLS(promise: EventLoopPromise<Void>?) {
        switch self.state {
        case .unwrapping, .closing:
            // We're shutting down here. Nothing has to be done, but we should keep track of this promise.
            if let promise = promise, let shutdownPromise = self.shutdownPromise {
                shutdownPromise.futureResult.cascade(to: promise)
            } else if let promise = promise {
                self.shutdownPromise = promise
            }

        case .idle:
            // We've never activated, it's easy to remove TLS from a connection that never had it.
            guard let storedContext = self.storedContext else {
                promise?.fail(NIOTLSUnwrappingError.invalidInternalState)
                return
            }

            self.state = .unwrapped
            self.shutdownPromise = promise
            self.channelUnwrap(context: storedContext)

        case .handshaking, .active, .inputClosed, .outputClosed, .additionalVerification:
            // Time to try to strip TLS.
            guard let storedContext = self.storedContext else {
                promise?.fail(NIOTLSUnwrappingError.invalidInternalState)
                return
            }

            self.state = .unwrapping(self.scheduleTimedOutShutdown(context: storedContext))
            self.shutdownPromise = promise
            self.doShutdownStep(context: storedContext)

        case .unwrapped:
            // We are already unwrapped. Succeed the promise, do nothing.
            promise?.succeed(())

        case .closed:
            promise?.fail(NIOTLSUnwrappingError.alreadyClosed)
        }
    }
}

// MARK: Code that handles buffering/unbuffering actions.
extension NIOSSLHandler {
    private typealias BufferedWrite = (data: ByteBuffer, promise: EventLoopPromise<Void>?)
    private enum BufferedAction {
        case closeOutput
        case write(BufferedWrite)
    }

    private func bufferWrite(data: ByteBuffer, promise: EventLoopPromise<Void>?) {
        switch self.state {
        case .idle, .handshaking, .additionalVerification, .active, .unwrapping, .closing, .unwrapped, .inputClosed:
            ()
        case .outputClosed:
            promise?.fail(ChannelError.outputClosed)
            return
        case .closed:
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        var data = data

        // Here we guard against the possibility that any of these writes are larger than CInt.max.
        // This is very unusual but it can happen. To work around it, we just pretend that there were
        // multiple writes.
        //
        // During the short writes we set the promise to `nil` to make sure they only arrive at the end.
        // Note that we make sure that there's always a single write, at the end, that holds the promise.
        while data.readableBytes > self.maxWriteSize, let slice = data.readSlice(length: self.maxWriteSize) {
            bufferedActions.append(.write((data: slice, promise: nil)))
        }

        assert(data.readableBytes <= maxWriteSize)
        bufferedActions.append(.write((data: data, promise: promise)))
    }

    private func bufferFlush() {
        bufferedActions.mark()
    }

    private func discardBufferedActions(reason: Error) {
        while let bufferedAction = self.bufferedActions.popFirst() {
            if case .write(let bufferedWrite) = bufferedAction {
                bufferedWrite.promise?.fail(reason)
            }
        }
    }

    private func doUnbufferActions(context: ChannelHandlerContext) {
        // Return early if the user hasn't called flush.
        guard bufferedActions.hasMark else {
            return
        }

        // These are some annoying variables we use to persist state across invocations of
        // our closures. A better version of this code might be able to simplify this somewhat.
        var promises: [EventLoopPromise<Void>] = []

        do {
            var invokeCloseOutput = false
            var bufferedActionsLoopCount = 0
            bufferedActionsLoop: while self.bufferedActions.hasMark, bufferedActionsLoopCount < 1000 {
                bufferedActionsLoopCount += 1
                var didWrite = false

                writeLoop: while self.bufferedActions.hasMark {
                    let element = self.bufferedActions.first!
                    switch element {
                    case .write(let bufferedWrite):
                        var data = bufferedWrite.data
                        let writeSuccessful = try self._encodeSingleWrite(buf: &data)
                        if writeSuccessful {
                            didWrite = true
                            if let promise = bufferedWrite.promise { promises.append(promise) }
                            _ = self.bufferedActions.removeFirst()
                        } else {
                            // The write into BoringSSL unsuccessful. Break the write loop so any
                            // data is written to the network before resuming.
                            break writeLoop
                        }
                    case .closeOutput:
                        invokeCloseOutput = true
                        _ = self.bufferedActions.removeFirst()
                        break writeLoop
                    }
                }

                // If we got this far and did a write, we should shove the data out to the
                // network.
                if didWrite {
                    let ourPromise: EventLoopPromise<Void>? = promises.flattenPromises(on: context.eventLoop)
                    self.writeDataToNetwork(context: context, promise: ourPromise)
                }

                // We detected a .closeOutput action in our action buffer. This means we
                // close the output after we have written all pending writes.
                if invokeCloseOutput {
                    self.state = .outputClosed
                    self.doShutdownStep(context: context)
                    self.discardBufferedActions(reason: ChannelError.outputClosed)
                    break bufferedActionsLoop
                }
            }

            // We spun the outer loop too many times, something isn't right so let's bail out
            // instead of looping any longer.
            if bufferedActionsLoopCount >= 1000 {
                assertionFailure(
                    "\(#function) looped too many times, please file a GitHub issue against swift-nio-ssl."
                )
                throw NIOSSLExtraError.noForwardProgress
            }
        } catch {
            // We encountered an error, it's cleanup time. Close ourselves down.
            channelClose(context: context, reason: error)

            // Fail any writes we've previously encoded but not flushed.
            for promise in promises { promise.fail(error) }

            // Fail close output promise if present
            let closeOutputPromise = self.closeOutputPromise
            self.closePromise = nil
            closeOutputPromise?.fail(error)

            // Fail everything else.
            self.discardBufferedActions(reason: error)
        }
    }

    /// Given a ByteBuffer to encode, passes it to BoringSSL and handles the result.
    private func _encodeSingleWrite(buf: inout ByteBuffer) throws -> Bool {
        let result = self.connection.writeDataToNetwork(&buf)

        switch result {
        case .complete:
            return true
        case .incomplete:
            // Ok, we can't write. Let's stop.
            return false
        case .failed(let err):
            // Once a write fails, all writes must fail. This includes prior writes
            // that successfully made it through BoringSSL.
            throw err
        }
    }
}

extension Array where Element == EventLoopPromise<Void> {
    /// Given an array of promises, flattens it out to a single promise.
    /// If the array is empty, returns nil.
    fileprivate func flattenPromises(on loop: EventLoop) -> EventLoopPromise<Void>? {
        guard self.count > 0 else {
            return nil
        }

        let ourPromise = loop.makePromise(of: Void.self)

        // We don't use cascade here because cascade has to create one closure per
        // promise. We can do better by creating only a single closure that dispatches
        // the result to all promises.
        ourPromise.futureResult.whenComplete { result in
            switch result {
            case .success:
                for result in self { result.succeed(()) }
            case .failure(let error):
                for result in self { result.fail(error) }
            }
        }

        return ourPromise
    }
}

// MARK:- Code for handling asynchronous handshake resumption.
extension NIOSSLHandler {
    internal func resumeHandshake() {
        guard let storedContext = self.storedContext else {
            // Oh well, the connection is dead. Do nothing.
            return
        }

        self.doHandshakeStep(context: storedContext)
    }
}
