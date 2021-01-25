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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import NIO

/// The result of an attempt to verify an X.509 certificate.
public enum NIOSSLVerificationResult {
    /// The certificate was successfully verified.
    case certificateVerified

    /// The certificate was not verified.
    case failed

    internal init(fromBoringSSLPreverify preverify: CInt) {
        switch preverify {
        case 1:
            self = .certificateVerified
        case 0:
            self = .failed
        default:
            preconditionFailure("Invalid preverify value: \(preverify)")
        }
    }
}

/// A custom verification callback.
///
/// This verification callback is usually called more than once per connection, as it is called once
/// per certificate in the peer's complete certificate chain (including the root CA). The calls proceed
/// from root to leaf, ending with the peer's leaf certificate. Each time it is invoked with 2 arguments:
///
/// 1. The result of the BoringSSL verification for this certificate
/// 2. The `SSLCertificate` for this level of the chain.
///
/// Please be cautious with calling out from this method. This method is always invoked on the event loop,
/// so you must not block or wait. It is not possible to return an `EventLoopFuture` from this method, as it
/// must not block or wait. Additionally, this method must take care to ensure that it does not cause any
/// ChannelHandler to recursively call back into the `NIOSSLHandler` that triggered it, as making re-entrant
/// calls into BoringSSL is not supported by SwiftNIO and leads to undefined behaviour.
///
/// In general, the only safe thing to do here is to either perform some cryptographic operations, to log,
/// or to store the `NIOSSLCertificate` somewhere for later consumption. The easiest way to be sure that the
/// `NIOSSLCertificate` is safe to consume is to wait for a user event that shows the handshake as completed,
/// or for channelInactive.
///
/// warning: This callback uses the old-style OpenSSL callback behaviour and is excessively complex to program with.
///    Instead, prefer using the NIOSSLCustomVerificationCallback style which receives the entire trust chain at once,
///    and also supports asynchronous certificate verification.
public typealias NIOSSLVerificationCallback = (NIOSSLVerificationResult, NIOSSLCertificate) -> NIOSSLVerificationResult


/// A custom verification callback that allows completely overriding the certificate verification logic of BoringSSL.
///
/// This verification callback is called no more than once per connection attempt. It is invoked with two arguments:
///
/// 1. The certificate chain presented by the peer, in the order the peer presented them (with the first certificate
///     being the leaf certificate presented by the peer).
/// 2. An `EventLoopPromise` that must be completed to signal the result of the verification.
///
/// Please be cautious with calling out from this method. This method is always invoked on the event loop,
/// so you must not block or wait. However, you may perform asynchronous work by leaving the event loop context:
/// when the verification is complete you must complete the provided `EventLoopPromise`.
///
/// This method must take care to ensure that it does not cause any `ChannelHandler` to recursively call back into
/// the `NIOSSLHandler` that triggered it, as making re-entrant calls into BoringSSL is not supported by SwiftNIO and
/// leads to undefined behaviour. It is acceptable to leave the event loop context and then call into the `NIOSSLHandler`,
/// as this will not be re-entrant.
///
/// Note that setting this callback will override _all_ verification logic that BoringSSL provides.
public typealias NIOSSLCustomVerificationCallback = ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) -> Void


/// A callback that can be used to implement `SSLKEYLOGFILE` support.
///
/// Wireshark can decrypt packet captures that contain encrypted TLS connections if they have access to the
/// session keys used to perform the encryption. These keys are normally stored in a file that has a specific
/// file format. This callback is the low-level primitive that can be used to write such a file.
///
/// When set, this callback will be invoked once per secret. The provided `ByteBuffer` will contain the bytes
/// that need to be written into the file, including the newline character.
///
/// - warning: Please be aware that enabling support for `SSLKEYLOGFILE` through this callback will put the secrecy of
///     your connections at risk. You should only do so when you are confident that it will not be possible to
///     extract those secrets unnecessarily.
///
public typealias NIOSSLKeyLogCallback = (ByteBuffer) -> Void


/// An object that provides helpers for working with a NIOSSLKeyLogCallback
internal struct KeyLogCallbackManager {
    private var callback: NIOSSLKeyLogCallback

    init(callback: @escaping NIOSSLKeyLogCallback) {
        self.callback = callback
    }
}

extension KeyLogCallbackManager {
    /// Called to log a string to the user.
    func log(_ stringPointer: UnsafePointer<CChar>) {
        let len = strlen(stringPointer)

        // We don't cache this because `log` can be called from arbitrary threads concurrently.
        var scratchBuffer = ByteBufferAllocator().buffer(capacity: len + 1)

        let bufferPointer = UnsafeRawBufferPointer(start: stringPointer, count: Int(len))
        scratchBuffer.writeBytes(bufferPointer)
        scratchBuffer.writeInteger(UInt8(ascii: "\n"))
        self.callback(scratchBuffer)
    }
}


/// A struct that provides helpers for working with a NIOSSLCustomVerificationCallback.
internal struct CustomVerifyManager {
    private var callback: CallbackType

    private var result: PendingResult = .notStarted

    init(callback: @escaping NIOSSLCustomVerificationCallback) {
        self.callback = .public(callback)
    }

    init(callback: @escaping InternalCallback) {
        self.callback = .internal(callback)
    }
}


extension CustomVerifyManager {
    private enum PendingResult: Hashable {
        case notStarted

        case pendingResult

        case complete(NIOSSLVerificationResult)
    }
}


extension CustomVerifyManager {
    mutating func process(on connection: SSLConnection) -> ssl_verify_result_t {
        // First, check if we have a result.
        switch self.result {
        case .complete(.certificateVerified):
            return ssl_verify_ok
        case .complete(.failed):
            return ssl_verify_invalid
        case .pendingResult:
            // Ask me again.
            return ssl_verify_retry
        case .notStarted:
            // The rest of this method handles this case.
            break
        }

        self.result = .pendingResult

        // Ok, no result. We need a promise for the user to use to supply a result.
        guard let eventLoop = connection.eventLoop else {
            // No event loop. We cannot possibly be negotiating here.
            preconditionFailure("No event loop present")
        }

        let promise = eventLoop.makePromise(of: NIOSSLVerificationResult.self)

        // We need to attach our "do the thing" callback. This will always invoke the "ask me again" API, and it will do so in a separate
        // event loop tick to avoid awkward re-entrancy with this method.
        promise.futureResult.whenComplete { result in
            // When we complete here we need to set our result state, and then ask to respin certificate verification.
            // If we can't respin verification because we've dropped the parent handler, that's fine, no harm no foul.
            // For that reason, we tolerate both the verify manager and the parent handler being nil.
            eventLoop.execute {
                // Note that we don't close over self here: that's to deal with the fact that this is a struct, and we don't want to
                // escape the mutable ownership of self.
                precondition(connection.customVerificationManager == nil || connection.customVerificationManager?.result == .some(.pendingResult))
                connection.customVerificationManager?.result = .complete(NIOSSLVerificationResult(result))
                connection.parentHandler?.asynchronousCertificateVerificationComplete()
            }
        }

        // Ok, let's do it.
        self.callback.invoke(on: connection, promise: promise)
        return ssl_verify_retry
    }
}


extension CustomVerifyManager {
    private enum CallbackType {
        case `public`(NIOSSLCustomVerificationCallback)
        case `internal`(InternalCallback)

        /// For user-supplied callbacks we need to give them public types. For internal ones, we just pass the
        /// `EventLoopPromise` object through.
        func invoke(on connection: SSLConnection, promise: EventLoopPromise<NIOSSLVerificationResult>) {
            switch self {
            case .public(let publicCallback):
                do {
                    let certificates = try connection.peerCertificateChain()
                    publicCallback(certificates, promise)
                } catch {
                    promise.fail(error)
                }

            case .internal(let internalCallback):
                internalCallback(promise)
            }
        }
    }

    internal typealias InternalCallback = (EventLoopPromise<NIOSSLVerificationResult>) -> Void
}


extension NIOSSLVerificationResult {
    init(_ result: Result<NIOSSLVerificationResult, Error>) {
        switch result {
        case .success(let s):
            self = s
        case .failure:
            self = .failed
        }
    }
}
