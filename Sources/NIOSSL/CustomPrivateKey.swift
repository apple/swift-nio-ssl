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

import NIOCore
@_implementationOnly import CNIOBoringSSL

/// `NIOSSLCustomPrivateKey` defines the interface of a custom, non-BoringSSL private key.
///
/// In a number of circumstances it is advantageous to store a TLS private key in some form of high-security storage,
/// such as a smart card. In these cases it is not possible to represent the TLS private key directly as a sequence
/// of bytes that BoringSSL will understand.
///
/// This protocol allows a type to implement callbacks that perform the specific operation required by the TLS handshake.
/// Implementers are required to specify what signature algorithms they support, and then must implement **only one** of
/// the `sign`/`decrypt` functions. For elliptic curve keys, implementers should implement `sign`. For RSA keys,
/// implementers should implement `sign` and, if supporting RSA key exchange in TLS versions before 1.3, you should
/// also implement `decrypt`.
///
/// If the same `NIOSSLCustomPrivateKey` implementation is used by multiple channels at once, then no synchronization
/// is imposed by SwiftNIO. The calls to the protocol requirements will be made on event loop threads, so if further
/// synchronization is required it is up to the implementer to provide it. Note that it is unacceptable to block in
/// these functions, and so potentially blocking operations must delegate to another thread.
public protocol NIOSSLCustomPrivateKey {
    /// The signature algorithms supported by this key.
    var signatureAlgorithms: [SignatureAlgorithm] { get }

    /// Called to perform a signing operation.
    ///
    /// The data being passed to the call has not been hashed, and it is the responsibility of the implementer
    /// to ensure that the data _is_ hashed before use. `algorithm` will control what hash algorithm should be used.
    /// This call will always execute on `channel.eventLoop`.
    ///
    /// This function should be implemented by both EC and RSA keys.
    ///
    /// - parameters:
    ///     - channel: The `Channel` representing the connection for which we are performing the signing operation.
    ///     - algorithm: The `SignatureAlgorithm` that should be used to generate the signature.
    ///     - data: The data to be signed.
    /// - returns: An `EventLoopFuture` that will be fulfilled with a `ByteBuffer` containing the signature bytes, if
    ///     the signing operation completes, or that will be failed with a relevant `Error` if the signature could not
    ///     be produced.
    func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer>

    /// Called to perform a decryption operation.
    ///
    /// The data being passed to the call should be decrypted using _raw_ RSA public key decryption, without padding.
    /// This call will always execute on `channel.eventLoop`.
    ///
    /// This function should only be implemented for RSA keys, and then only if you support RSA key exchange. If you
    /// are only using TLS 1.3 and later, this function is entirely unnecessary and it will never be called.
    ///
    /// - parameters:
    ///     - channel: The `Channel` representing the connection for which we are performing the decryption operation.
    ///     - data: The data to be decrypted.
    /// - returns: An `EventLoopFuture` that will be fulfilled with a `ByteBuffer` containing the decrypted bytes, if
    ///     the decryption operation completes, or that will be failed with a relevant `Error` if the decrypted bytes
    ///     could not be produced.
    func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer>
}

/// This is a type-erased wrapper that can be used to encapsulate a NIOSSLCustomPrivateKey and provide it with
/// hashability and equatability.
///
/// While generally speaking type-erasure has some nasty performance problems, we only need the type-erasure for
/// Hashable conformance, which we don't use in any production code: only the tests use it. To that end, we don't
/// mind too much that we need to do this.
@usableFromInline
internal struct AnyNIOSSLCustomPrivateKey: NIOSSLCustomPrivateKey, Hashable {
    @usableFromInline let _value: NIOSSLCustomPrivateKey

    @usableFromInline let _equalsFunction: (NIOSSLCustomPrivateKey) -> Bool

    @usableFromInline let _hashFunction: (inout Hasher) -> Void

    @inlinable init<CustomKey: NIOSSLCustomPrivateKey & Hashable>(_ key: CustomKey) {
        self._value = key
        self._equalsFunction = { ($0 as? CustomKey) == key }
        self._hashFunction = { $0.combine(key) }
    }

    // This method does not need to be @inlinable for performance, but it needs to be _at least_
    // @usableFromInline as it's a protocol requirement on a @usableFromInline type.
    @inlinable var signatureAlgorithms: [SignatureAlgorithm] {
        return self._value.signatureAlgorithms
    }

    // This method does not need to be @inlinable for performance, but it needs to be _at least_
    // @usableFromInline as it's a protocol requirement on a @usableFromInline type.
    @inlinable func sign(channel: Channel, algorithm: SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        return self._value.sign(channel: channel, algorithm: algorithm, data: data)
    }

    // This method does not need to be @inlinable for performance, but it needs to be _at least_
    // @usableFromInline as it's a protocol requirement on a @usableFromInline type.
    @inlinable func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        return self._value.decrypt(channel: channel, data: data)
    }

    // This method does not need to be @inlinable for performance, but it needs to be _at least_
    // @usableFromInline as it's a protocol requirement on a @usableFromInline type.
    @inlinable func hash(into hasher: inout Hasher) {
        self._hashFunction(&hasher)
    }

    // This method does not need to be @inlinable for performance, but it needs to be _at least_
    // @usableFromInline as it's a protocol requirement on a @usableFromInline type.
    @inlinable static func ==(lhs: AnyNIOSSLCustomPrivateKey, rhs: AnyNIOSSLCustomPrivateKey) -> Bool {
        return lhs._equalsFunction(rhs._value)
    }
}

extension SSLConnection {
    fileprivate var customKey: NIOSSLCustomPrivateKey? {
        guard case .some(.privateKey(let key)) = self.parentContext.configuration.privateKey,
              case .custom(let customKey) = key.representation else {
            return nil
        }

        return customKey
    }

    fileprivate func customPrivateKeySign(
        signatureAlgorithm: UInt16,
        in: UnsafeBufferPointer<UInt8>
    ) -> ssl_private_key_result_t {
        precondition(self.customPrivateKeyResult == nil)

        guard let customKey = self.customKey else {
            preconditionFailure()
        }

        let wrappedAlgorithm = SignatureAlgorithm(rawValue: signatureAlgorithm)
        guard customKey.signatureAlgorithms.contains(wrappedAlgorithm) else {
            return ssl_private_key_failure
        }

        // This force-unwrap pair is safe: we can only handshake while we're in a pipeline.
        let channel = self.parentHandler!.channel!
        var inputBytes = channel.allocator.buffer(capacity: `in`.count)
        inputBytes.writeBytes(`in`)

        let result = customKey.sign(channel: channel, algorithm: wrappedAlgorithm, data: inputBytes)
        result.whenComplete { signingResult in
            self.storeCustomPrivateKeyResult(signingResult, channel: channel)
        }

        return ssl_private_key_retry
    }

    fileprivate func customPrivateKeyDecrypt(
        in: UnsafeBufferPointer<UInt8>
    ) -> ssl_private_key_result_t {
        precondition(self.customPrivateKeyResult == nil)

        guard let customKey = self.customKey else {
            preconditionFailure()
        }

        // This force-unwrap pair is safe: we can only handshake while we're in a pipeline.
        let channel = self.parentHandler!.channel!
        var inputBytes = channel.allocator.buffer(capacity: `in`.count)
        inputBytes.writeBytes(`in`)

        let result = customKey.decrypt(channel: channel, data: inputBytes)
        result.whenComplete { decryptionResult in
            self.storeCustomPrivateKeyResult(decryptionResult, channel: channel)
        }

        return ssl_private_key_retry
    }

    fileprivate func customPrivateKeyComplete(out: inout UnsafeMutableBufferPointer<UInt8>) -> ssl_private_key_result_t {
        switch self.customPrivateKeyResult {
        case .none:
            return ssl_private_key_retry
        case .some(.failure):
            return ssl_private_key_failure
        case .some(.success(let signingResult)):
            guard signingResult.readableBytes <= out.count else {
                return ssl_private_key_failure
            }

            let (_, lastIndex) = out.initialize(from: signingResult.readableBytesView)
            out = UnsafeMutableBufferPointer(rebasing: out[..<lastIndex])
            return ssl_private_key_success
        }
    }

    private func storeCustomPrivateKeyResult(_ result: Result<ByteBuffer, Error>, channel: Channel) {
        // When we complete here we need to set our result state, and then ask to respin the handshake.
        // If we can't respin the handshake because we've dropped the parent handler, that's fine, no harm no foul.
        // For that reason, we tolerate both the verify manager and the parent handler being nil.
        channel.eventLoop.execute {
            precondition(self.customPrivateKeyResult == nil)
            self.customPrivateKeyResult = result
            self.parentHandler?.resumeHandshake()
        }
    }
}

// We heap-allocate the SSL_PRIVATE_KEY_METHOD we need because we can't define a static stored property with fixed address
// in Swift.
internal let customPrivateKeyMethod: UnsafePointer<SSL_PRIVATE_KEY_METHOD> = {
    let pointer = UnsafeMutablePointer<SSL_PRIVATE_KEY_METHOD>.allocate(capacity: 1)
    pointer.pointee = .init(sign: customKeySign, decrypt: customKeyDecrypt, complete: customKeyComplete)
    return UnsafePointer(pointer)
}()

/// This is our entry point from BoringSSL when we've been asked to do a sign.
fileprivate func customKeySign(
    ssl: OpaquePointer?, out: UnsafeMutablePointer<UInt8>?, outLen: UnsafeMutablePointer<Int>?,
    maxOut: size_t, signatureAlgorithm: UInt16, in: UnsafePointer<UInt8>?, inLen: Int
) -> ssl_private_key_result_t {
    guard let ssl = ssl, out != nil, let outLen = outLen, let `in` = `in` else {
        preconditionFailure()
    }

    let connection = SSLConnection.loadConnectionFromSSL(ssl)
    let inBuffer = UnsafeBufferPointer(start: `in`, count: inLen)

    // We never return anything here.
    outLen.pointee = 0

    return connection.customPrivateKeySign(signatureAlgorithm: signatureAlgorithm, in: inBuffer)
}

/// This is our entry point from BoringSSL when we've been asked to do a decrypt.
fileprivate func customKeyDecrypt(
    ssl: OpaquePointer?, out: UnsafeMutablePointer<UInt8>?, outLen: UnsafeMutablePointer<Int>?,
    maxOut: Int, in: UnsafePointer<UInt8>?, inLen: Int
) -> ssl_private_key_result_t {
    guard let ssl = ssl, out != nil, let outLen = outLen, let `in` = `in` else {
        preconditionFailure()
    }

    let connection = SSLConnection.loadConnectionFromSSL(ssl)
    let inBuffer = UnsafeBufferPointer(start: `in`, count: inLen)

    // We never return anything here.
    outLen.pointee = 0

    return connection.customPrivateKeyDecrypt(in: inBuffer)
}


/// When BoringSSL is asking if we're done with our key operation, we come here.
fileprivate func customKeyComplete(
    ssl: OpaquePointer?, out: UnsafeMutablePointer<UInt8>?, outLen: UnsafeMutablePointer<Int>?,
    maxOut: Int
) -> ssl_private_key_result_t {
    guard let ssl = ssl, let out = out, let outLen = outLen else {
        preconditionFailure()
    }

    let connection = SSLConnection.loadConnectionFromSSL(ssl)
    var outBuffer = UnsafeMutableBufferPointer(start: out, count: maxOut)
    let result = connection.customPrivateKeyComplete(out: &outBuffer)

    if result != ssl_private_key_success {
        // We need to set outLen to zero here.
        outLen.pointee = 0
    } else {
        outLen.pointee = outBuffer.count
    }

    return result
}
