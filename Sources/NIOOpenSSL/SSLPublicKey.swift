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

import CNIOOpenSSL

/// An `OpenSSLPublicKey` is an abstract handle to a public key owned by OpenSSL.
///
/// This object is of minimal utility, as it cannot be used for very many operations
/// in `NIOOpenSSL`. Its primary purpose is to allow extracting public keys from
/// `OpenSSLCertificate` objects to be serialized, so that they can be passed to
/// general-purpose cryptography libraries.
public class OpenSSLPublicKey {
    private let ref: OpaquePointer

    fileprivate init(withOwnedReference ref: OpaquePointer) {
        self.ref = ref
    }

    deinit {
        EVP_PKEY_free(.make(optional: self.ref))
    }
}

// MARK:- Helpful initializers
extension OpenSSLPublicKey {
    /// Create an `OpenSSLPublicKey` object from an internal `EVP_PKEY` pointer.
    ///
    /// This method expects `pointer` to be passed at +1, and consumes that reference.
    ///
    /// - parameters:
    ///    - pointer: A pointer to an `EVP_PKEY` structure containing the public key.
    /// - returns: An `OpenSSLPublicKey` wrapping the pointer.
    internal static func fromInternalPointer(takingOwnership pointer: OpaquePointer) -> OpenSSLPublicKey {
        return OpenSSLPublicKey(withOwnedReference: pointer)
    }
}

extension OpenSSLPublicKey {
    /// Extracts the bytes of this public key in the SubjectPublicKeyInfo format.
    ///
    /// The SubjectPublicKeyInfo format is defined in RFC 5280. In addition to the raw key bytes, it also
    /// provides an identifier of the algorithm, ensuring that the key can be unambiguously decoded.
    ///
    /// - returns: The DER-encoded SubjectPublicKeyInfo bytes for this public key.
    /// - throws: If an error occurred while serializing the key.
    public func toSPKIBytes() throws -> [UInt8] {
        guard let bio = BIO_new(BIO_s_mem()) else {
            throw NIOOpenSSLError.unableToAllocateOpenSSLObject
        }

        defer {
            BIO_free(bio)
        }

        let rc = i2d_PUBKEY_bio(bio, .make(optional: self.ref))
        guard rc == 1 else {
            let errorStack = OpenSSLError.buildErrorStack()
            throw OpenSSLError.unknownError(errorStack)
        }

        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CNIOOpenSSL_BIO_get_mem_data(bio, &dataPtr)

        guard let bytes = dataPtr.map({ UnsafeMutableRawBufferPointer(start: $0, count: length) }) else {
            throw NIOOpenSSLError.unableToAllocateOpenSSLObject
        }

        return Array(bytes)
    }
}
