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

#if canImport(Darwin)
import Darwin.C
#elseif canImport(Musl)
import Musl
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Bionic)
import Bionic
#else
#error("unsupported os")
#endif

/// The result of an attempt to verify an X.509 certificate.
public enum NIOSSLVerificationResult: Sendable {
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

/// The result of an attempt to verify an X.509 certificate, with associated metadata if the certificate was successfully verified.
public enum NIOSSLVerificationResultWithMetadata: Sendable, Hashable {
    /// The certificate was successfully verified; the associated value contains metadata captured during verification.
    case certificateVerified(VerificationMetadata)

    /// The certificate was not verified.
    case failed
}

/// The metadata captured during the verification of an X.509 certificate.
public struct VerificationMetadata: Sendable, Hashable {
    /// A container for the validated certificate chain: an array of certificates forming a verified and ordered chain
    /// of trust, starting from the peer's leaf certificate to a trusted root certificate.
    public var validatedCertificateChain: ValidatedCertificateChain?

    /// Creates an instance with the peer's *validated* certificate chain.
    ///
    /// - Parameter validatedCertificateChain: An optional *validated* certificate chain. If provided, it must **only**
    /// contain the **validated** chain of trust that was built and verified from the certificates presented by the peer.
    public init(_ validatedCertificateChain: ValidatedCertificateChain?) {
        self.validatedCertificateChain = validatedCertificateChain
    }
}

/// A custom verification callback.
///
/// This verification callback is usually called more than once per connection, as it is called once
/// per certificate in the peer's complete certificate chain (including the root CA). The calls proceed
/// from root to leaf, ending with the peer's leaf certificate. Each time it is invoked with 2 arguments:
///
/// 1. The result of the BoringSSL verification for this certificate
/// 2. The ``NIOSSLCertificate`` for this level of the chain.
///
/// Please be cautious with calling out from this method. This method is always invoked on the event loop,
/// so you must not block or wait. It is not possible to return an `EventLoopFuture` from this method, as it
/// must not block or wait. Additionally, this method must take care to ensure that it does not cause any
/// ChannelHandler to recursively call back into the ``NIOSSLHandler`` that triggered it, as making re-entrant
/// calls into BoringSSL is not supported by SwiftNIO and leads to undefined behaviour.
///
/// In general, the only safe thing to do here is to either perform some cryptographic operations, to log,
/// or to store the ``NIOSSLCertificate`` somewhere for later consumption. The easiest way to be sure that the
/// ``NIOSSLCertificate`` is safe to consume is to wait for a user event that shows the handshake as completed,
/// or for channelInactive.
///
/// > Warning: This callback uses the old-style OpenSSL callback behaviour and is excessively complex to program with.
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
/// the ``NIOSSLHandler`` that triggered it, as making re-entrant calls into BoringSSL is not supported by SwiftNIO and
/// leads to undefined behaviour. It is acceptable to leave the event loop context and then call into the ``NIOSSLHandler``,
/// as this will not be re-entrant.
///
/// - Warning: Note that setting this callback will override _all_ verification logic that BoringSSL provides.
public typealias NIOSSLCustomVerificationCallback = ([NIOSSLCertificate], EventLoopPromise<NIOSSLVerificationResult>) ->
    Void

/// A custom verification callback that allows completely overriding the certificate verification logic of BoringSSL.
/// The only difference between this callback and ``NIOSSLCustomVerificationCallback`` is that this callback allows
/// the peer's validated certificate chain to be returned.
///
/// This verification callback is called no more than once per connection attempt. It is invoked with two arguments:
///
/// 1. The certificate chain presented by the peer, in the order the peer presented them (with the first certificate
///     being the leaf certificate presented by the peer).
/// 2. An `EventLoopPromise` that must be completed to signal the result of the verification. The promise must be
///    fulfilled with a ``NIOSSLVerificationResultWithMetadata`` value which contains the validated chain.
///
/// Please be cautious with calling out from this method. This method is always invoked on the event loop,
/// so you must not block or wait. However, you may perform asynchronous work by leaving the event loop context:
/// when the verification is complete you must complete the provided `EventLoopPromise`.
///
/// This method must take care to ensure that it does not cause any `ChannelHandler` to recursively call back into
/// the ``NIOSSLHandler`` that triggered it, as making re-entrant calls into BoringSSL is not supported by SwiftNIO and
/// leads to undefined behaviour. It is acceptable to leave the event loop context and then call into the ``NIOSSLHandler``,
/// as this will not be re-entrant.
///
/// - Warning: Setting this callback will override _all_ verification logic that BoringSSL provides. Therefore, a
///   validated chain must be derived *within* this callback (potentially involving fetching additional intermediate
///   certificates). The *validated* certificate chain returned in the promise result **must** be a verified path
///   to a trusted root. Importantly, the certificates presented by the peer should not be assumed to be valid.
public typealias NIOSSLCustomVerificationCallbackWithMetadata = (
    [NIOSSLCertificate],
    EventLoopPromise<NIOSSLVerificationResultWithMetadata>
) -> Void

/// A custom verification callback that allows additional peer certificate verification logic after the logic of BoringSSL has completed successfully.
///
/// It is invoked with two arguments:
/// 1. The verified leaf certificate from the peer certificate chain
/// 2. The channel to which the certificate belongs
///
/// The handshake will only succeed if the returned promise completes successfully.
///
/// - warning: This API is not guaranteed to be stable and is likely to be changed without further notice, hence the underscore prefix.
public typealias _NIOAdditionalPeerCertificateVerificationCallback = (NIOSSLCertificate, Channel) -> EventLoopFuture<
    Void
>

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
public typealias NIOSSLKeyLogCallback = @Sendable (ByteBuffer) -> Void

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

/// PSK Server Context provided to the callback.
public struct PSKServerContext: Sendable, Hashable {
    /// Optional identity hint provided to the client by the server.
    public let hint: String?
    /// Identity provided by the client to the server.
    public let clientIdentity: String
    /// Maximum length of the returned PSK.
    public let maxPSKLength: Int

    /// Constructs a ``PSKServerContext``.
    ///
    /// - parameter hint: Optional identity hint provided to the client.
    /// - parameter clientIdentity: Client identity received from the client.
    /// - parameter maxPSKLength: Maximum possible length of the Pre Shared Key.
    public init(hint: String?, clientIdentity: String, maxPSKLength: Int) {
        self.hint = hint
        self.clientIdentity = clientIdentity
        self.maxPSKLength = maxPSKLength
    }
}

/// PSK Client Context provided to the callback.
public struct PSKClientContext: Sendable, Hashable {
    /// Optional identity hint provided by the server to the client.
    public let hint: String?
    /// Maximum length of the returned PSK.
    public let maxPSKLength: Int

    /// Constructs a ``PSKClientContext``.
    ///
    /// - parameter hint: Optional identity hint provided by the server.
    /// - parameter maxPSKLength: Maximum possible length of the Pre Shared Key.
    public init(hint: String?, maxPSKLength: Int) {
        self.hint = hint
        self.maxPSKLength = maxPSKLength
    }
}

/// PSK Server Identity response type used in the callback.
public struct PSKServerIdentityResponse: Sendable {
    /// The negotiated PSK.
    public var key: NIOSSLSecureBytes

    /// Constructs a ``PSKServerIdentityResponse``.
    ///
    /// - parameter key: The negotiated PSK.
    public init(key: NIOSSLSecureBytes) {
        self.key = key
    }
}
/// PSK Client Identity response type used in the callback.
public struct PSKClientIdentityResponse: Sendable {
    /// The negotiated PSK.
    public var key: NIOSSLSecureBytes

    /// The identity of the PSK.
    public var identity: String

    /// Constructs a ``PSKClientIdentityResponse``.
    ///
    /// - parameter key: The negotiated PSK.
    /// - parameter identity: The identity of the PSK.
    public init(key: NIOSSLSecureBytes, identity: String) {
        self.key = key
        self.identity = identity
    }
}

/// A structure representing values from client extensions in the SSL/TLS handshake.
///
/// This struct contains values obtained from the client hello message extensions during the TLS handshake process and
/// can be manipulated or introspected by the `NIOSSLContextCallback` to alter the TLS handshake behaviour dynamically
/// based on these values.
public struct NIOSSLClientExtensionValues: Hashable, Sendable {

    /// The hostname value from the Server Name Indication (SNI) extension.
    ///
    /// This value, if available, indicates the requested server hostname by the client.
    /// In a context where a service is handling multiple hostnames (virtual hosts, for example),
    /// this value could be used to decide which SSLContext to use for the handshake.
    public var serverHostname: String?

    /// Initializes a new `NIOSSLClientExtensionValues` struct.
    ///
    /// - parameter serverHostname: The hostname value from the SNI extension.
    public init(serverHostname: String?) {
        self.serverHostname = serverHostname
    }
}

/// A structure representing changes to the SSL/TLS configuration that can be applied
/// after the client hello message extensions have been processed.
public struct NIOSSLContextConfigurationOverride: Sendable {

    /// The new certificate chain to use for the handshake.
    public var certificateChain: [NIOSSLCertificateSource]?

    /// The new private key to use for the handshake.
    public var privateKey: NIOSSLPrivateKeySource?

    public init() {}
}

extension NIOSSLContextConfigurationOverride {

    /// Return inside `NIOSSLContextCallback` when there are no changes to be made
    public static let noChanges = Self()
}

/// A callback that can used to support multiple or dynamic TLS hosts.
///
/// When set, this callback will be invoked once per TLS hello. The provided `NIOSSLClientExtensionValues` will contain the
/// host name indicated in the TLS client hello.
///
/// Within this callback, the user can create and return a new `NIOSSLContextConfigurationOverride` for the given host,
/// and the delta will be applied to the current handshake configuration.
///
public typealias NIOSSLContextCallback =
    @Sendable (
        NIOSSLClientExtensionValues, EventLoopPromise<NIOSSLContextConfigurationOverride>
    ) -> Void

/// A struct that provides helpers for working with a NIOSSLContextCallback.
internal struct CustomContextManager: Sendable {
    private let callback: NIOSSLContextCallback

    private var state: State

    init(callback: @escaping NIOSSLContextCallback) {
        self.callback = callback
        self.state = .notStarted
    }
}

extension CustomContextManager {
    private enum State {
        case notStarted

        case pendingResult

        case complete(Result<NIOSSLContextConfigurationOverride, Error>)
    }
}

extension CustomContextManager {
    internal var loadContextError: (any Error)? {
        switch self.state {
        case .complete(.failure(let error)):
            return error
        default:
            return nil
        }
    }
}

extension CustomContextManager {
    mutating func loadContext(ssl: OpaquePointer) -> Result<NIOSSLContextConfigurationOverride, Error>? {
        switch state {
        case .pendingResult:
            // In the pending case we return nil
            return nil
        case .complete(let result):
            // In the complete we can return our result
            return result
        case .notStarted:
            // Load the attached connection so we can resume handshake when future resolves
            let connection = SSLConnection.loadConnectionFromSSL(ssl)

            guard let eventLoop = connection.eventLoop else {
                preconditionFailure(
                    """
                        SSL_CTX_set_cert_cb was executed without an event loop assigned to the connection.
                        This should not be possible, please file an issue.
                    """
                )
            }

            // Construct extension values to be passed to callback
            let cServerHostname = CNIOBoringSSL_SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)
            let serverHostname = cServerHostname.map { String(cString: $0) }
            let values = NIOSSLClientExtensionValues(serverHostname: serverHostname)

            // Before invoking the user callback we can update our state to pending
            self.state = .pendingResult

            // We're responsible for creating the promise and the user provided callback will fulfill it
            let promise = eventLoop.makePromise(of: NIOSSLContextConfigurationOverride.self)
            self.callback(values, promise)

            promise.futureResult.assumeIsolated().whenComplete { result in
                // Ensure we execute any completion on the next event loop tick
                // This ensures that we suspend before calling resume
                eventLoop.assumeIsolated().execute {
                    connection.customContextManager?.state = .complete(result)
                    connection.parentHandler?.resumeHandshake()
                }
            }

            return nil
        }
    }

    mutating func setLoadContextError(_ error: any Error) {
        self.state = .complete(.failure(error))
    }
}

/// The callback used for providing a PSK on the client side.
///
/// The callback is invoked on the event loop with the PSK hint. This callback must complete synchronously: it cannot return a future.
/// Additionally, as it is invoked on the NIO event loop, it is not possible for this to perform any I/O. As a result, lookups must be quick.
public typealias NIOPSKClientIdentityCallback = @Sendable (String) throws -> PSKClientIdentityResponse

/// The callback used for providing a PSK on the client side.
///
/// The callback is invoked on the event loop with a PSK context.
/// The context include the optional hint provided by the server.
/// This callback must complete synchronously: it cannot return a future.
/// Additionally, as it is invoked on the NIO event loop, it is not possible for this to perform any I/O. As a result, lookups must be quick.
public typealias NIOPSKClientIdentityProvider = @Sendable (PSKClientContext) throws -> PSKClientIdentityResponse

/// The callback used for providing a PSK on the server side.
///
/// The callback is invoked on the event loop with the PSK hint provided by the server, and the PSK identity provided by the client.
/// This callback must complete synchronously: it cannot return a future. Additionally, as it is invoked on the NIO event loop, it is
/// not possible for this to perform any I/O. As a result, lookups must be quick.
public typealias NIOPSKServerIdentityCallback = @Sendable (String, String) throws -> PSKServerIdentityResponse

/// The callback used for providing a PSK on the server side.
///
/// The callback is invoked on the event loop with a PSK context provided by the server and the client, and the PSK identity provided by the client
/// The context includes the optional hint.
/// This callback must complete synchronously: it cannot return a future. Additionally, as it is invoked on the NIO event loop, it is
/// not possible for this to perform any I/O. As a result, lookups must be quick.
public typealias NIOPSKServerIdentityProvider = @Sendable (PSKServerContext) throws -> PSKServerIdentityResponse

/// Allow internally to maintain the compatibility with the deprecated callback
internal enum _NIOPSKServerIdentityProvider {
    case callback(NIOPSKServerIdentityCallback)
    case provider(NIOPSKServerIdentityProvider)
}

/// Allow internally to maintain the compatibility with the deprecated callback
internal enum _NIOPSKClientIdentityProvider {
    case callback(NIOPSKClientIdentityCallback)
    case provider(NIOPSKClientIdentityProvider)
}

/// A struct that provides helpers for working with a NIOSSLCustomVerificationCallback.
internal struct CustomVerifyManager {
    private var callback: CallbackType

    private var result: PendingResult = .notStarted

    /// Contains the metadata that the callback returned. As such, this property will *only* contain a value if
    /// `self.result` is `.complete` (and if the callback promise returns metadata).
    var verificationMetadata: VerificationMetadata?

    init(callback: @escaping NIOSSLCustomVerificationCallback) {
        self.callback = .public(callback)
    }

    init(callback: @escaping NIOSSLCustomVerificationCallbackWithMetadata) {
        self.callback = .publicWithMetadata(callback)
    }

    init(callback: @escaping InternalCallback) {
        self.callback = .internal(callback)
    }
}

extension CustomVerifyManager {
    fileprivate enum PendingResult: Hashable {
        case notStarted

        case pendingResult

        case complete(NIOSSLVerificationResult)

        case completeWithMetadata(NIOSSLVerificationResultWithMetadata)
    }

    fileprivate protocol PendingResultConvertible {
        static func pendingResult(_ result: Result<Self, any Error>) -> PendingResult
    }
}

extension CustomVerifyManager {
    mutating func process(on connection: SSLConnection) -> ssl_verify_result_t {
        // First, check if we have a result.
        switch self.result {
        case .complete(.certificateVerified):
            return ssl_verify_ok
        case .completeWithMetadata(.certificateVerified(let metadata)):
            // Extract the metadata and store it within `self`.
            self.verificationMetadata = metadata
            return ssl_verify_ok
        case .complete(.failed), .completeWithMetadata(.failed):
            return ssl_verify_invalid
        case .pendingResult:
            // Ask me again.
            return ssl_verify_retry
        case .notStarted:
            // The rest of this method handles this case.
            break
        }

        self.result = .pendingResult

        // Ok, no result. We must invoke the callback.
        self.callback.invoke(on: connection)

        return ssl_verify_retry
    }
}

extension CustomVerifyManager {
    private enum CallbackType {
        case `public`(NIOSSLCustomVerificationCallback)
        case publicWithMetadata(NIOSSLCustomVerificationCallbackWithMetadata)
        case `internal`(InternalCallback)

        // Prepares the promise that will be provided as an argument to the callback.
        private static func preparePromise<CallbackResult: PendingResultConvertible>(
            on connection: SSLConnection
        ) -> EventLoopPromise<CallbackResult> {
            // We need a promise for the user to use to supply a result.
            guard let eventLoop = connection.eventLoop else {
                // No event loop. We cannot possibly be negotiating here.
                preconditionFailure("No event loop present")
            }

            let promise = eventLoop.makePromise(of: CallbackResult.self)

            // We need to attach our "do the thing" callback. This will always invoke the "ask me again" API, and it will do so in a separate
            // event loop tick to avoid awkward re-entrancy with this method.
            promise.futureResult.assumeIsolated().whenComplete { result in
                // When we complete here we need to set our result state, and then ask to respin certificate verification.
                // If we can't respin verification because we've dropped the parent handler, that's fine, no harm no foul.
                // For that reason, we tolerate both the verify manager and the parent handler being nil.
                eventLoop.assumeIsolated().execute {
                    // Note that we don't close over self here: that's to deal with the fact that this is a struct, and we don't want to
                    // escape the mutable ownership of self.
                    precondition(
                        connection.customVerificationManager == nil
                            || connection.customVerificationManager?.result == .some(.pendingResult)
                    )
                    connection.customVerificationManager?.result = CallbackResult.pendingResult(result)
                    connection.parentHandler?.resumeHandshake()
                }
            }

            return promise
        }

        /// For user-supplied callbacks we need to give them public types. For internal ones, we just pass the
        /// `EventLoopPromise` object through.
        func invoke(on connection: SSLConnection) {
            switch self {
            case .internal(let internalCallback):
                let promise: EventLoopPromise<NIOSSLVerificationResult> = Self.preparePromise(on: connection)

                internalCallback(promise)
            case .public(let callback):
                let promise: EventLoopPromise<NIOSSLVerificationResult> = Self.preparePromise(on: connection)

                do {
                    callback(try connection.peerCertificateChain(), promise)
                } catch {
                    promise.fail(error)
                }
            case .publicWithMetadata(let callback):
                let promise: EventLoopPromise<NIOSSLVerificationResultWithMetadata> = Self.preparePromise(
                    on: connection
                )

                do {
                    callback(try connection.peerCertificateChain(), promise)
                } catch {
                    promise.fail(error)
                }
            }
        }
    }

    internal typealias InternalCallback = (EventLoopPromise<NIOSSLVerificationResult>) -> Void
}

extension NIOSSLVerificationResult: CustomVerifyManager.PendingResultConvertible {
    fileprivate static func pendingResult(_ result: Result<Self, Error>) -> CustomVerifyManager.PendingResult {
        switch result {
        case .success(let s):
            .complete(s)
        case .failure:
            .complete(.failed)
        }
    }
}

extension NIOSSLVerificationResultWithMetadata: CustomVerifyManager.PendingResultConvertible {
    fileprivate static func pendingResult(_ result: Result<Self, Error>) -> CustomVerifyManager.PendingResult {
        switch result {
        case .success(let s):
            .completeWithMetadata(s)
        case .failure:
            .completeWithMetadata(.failed)
        }
    }
}

/// Represents a *validated* certificate chain, an array of certificates forming a verified and ordered trust path,
/// starting from the peer's certificate to a trusted root certificate.
public struct ValidatedCertificateChain: Sendable, Collection, RandomAccessCollection, Hashable {
    let validatedChain: [NIOSSLCertificate]

    public typealias Index = Int
    public typealias Element = NIOSSLCertificate

    public var startIndex: Index { self.validatedChain.startIndex }
    public var endIndex: Index { self.validatedChain.endIndex }

    public subscript(index: Index) -> Element {
        self.validatedChain[index]
    }

    public func index(after i: Index) -> Index {
        self.validatedChain.index(after: i)
    }

    /// Creates a `ValidatedCertificateChain` instance from an array of certificates forming a *verified* chain of trust.
    ///
    /// - Parameter validatedChain: An array of `NIOSSLCertificate` objects, representing the verified and ordered trust
    ///   path, starting from the peer's certificate (first element) to a trusted root certificate (last element), with
    ///   intermediate certificates ordered in between.
    ///
    /// - Important: Do not blindly pass in the array of certificates presented by the peer; the array *must* represent
    ///   a fully validated and trusted chain.
    ///
    /// - Precondition: `validatedChain` must contain at least one certificate.
    public init(_ validatedChain: [NIOSSLCertificate]) {
        precondition(validatedChain.count > 0, "The provided validated chain must have at least one certificate")
        self.validatedChain = validatedChain
    }

    /// Returns the first element of the chain: the leaf certificate.
    public var leaf: NIOSSLCertificate {
        // We can safely force unwrap: the initializer enforces at least one element in `validatedChain`
        self.validatedChain.first!
    }
}
