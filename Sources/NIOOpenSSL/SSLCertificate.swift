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

import CNIOBoringSSL
import CNIOBoringSSLShims
import NIO

/// A reference to an OpenSSL Certificate object (`X509 *`).
///
/// This thin wrapper class allows us to use ARC to automatically manage
/// the memory associated with this TLS certificate. That ensures that OpenSSL
/// will not free the underlying buffer until we are done with the certificate.
///
/// This class also provides several convenience constructors that allow users
/// to obtain an in-memory representation of a TLS certificate from a buffer of
/// bytes or from a file path.
public class OpenSSLCertificate {
    internal let ref: UnsafeMutablePointer<X509>

    internal enum AlternativeName {
        case dnsName([UInt8])
        case ipAddress(IPAddress)
    }

    internal enum IPAddress {
        case ipv4(in_addr)
        case ipv6(in6_addr)
    }

    private init(withReference ref: UnsafeMutablePointer<X509>) {
        self.ref = ref
    }

    /// Create an OpenSSLCertificate from a file at a given path in either PEM or
    /// DER format.
    ///
    /// Note that this method will only ever load the first certificate from a given file.
    public convenience init (file: String, format: OpenSSLSerializationFormats) throws {
        let fileObject = try Posix.fopen(file: file, mode: "rb")
        defer {
            fclose(fileObject)
        }

        let x509: UnsafeMutablePointer<X509>?
        switch format {
        case .pem:
            x509 = CNIOBoringSSL_PEM_read_X509(fileObject, nil, nil, nil)
        case .der:
            x509 = CNIOBoringSSL_d2i_X509_fp(fileObject, nil)
        }

        if x509 == nil {
            throw NIOOpenSSLError.failedToLoadCertificate
        }

        self.init(withReference: x509!)
    }

    /// Create an OpenSSLCertificate from a buffer of bytes in either PEM or
    /// DER format.
    public convenience init (buffer: [Int8], format: OpenSSLSerializationFormats) throws  {
        let ref = buffer.withUnsafeBytes { (ptr) -> UnsafeMutablePointer<X509>? in
            let bio = CNIOBoringSSL_BIO_new_mem_buf(UnsafeMutableRawPointer(mutating: ptr.baseAddress!), Int32(ptr.count))!

            defer {
                CNIOBoringSSL_BIO_free(bio)
            }

            switch format {
            case .pem:
                return CNIOBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
            case .der:
                return CNIOBoringSSL_d2i_X509_bio(bio, nil)
            }
        }

        if ref == nil {
            throw NIOOpenSSLError.failedToLoadCertificate
        }

        self.init(withReference: ref!)
    }

    /// Create an OpenSSLCertificate wrapping a pointer into OpenSSL.
    ///
    /// This is a function that should be avoided as much as possible because it plays poorly with
    /// OpenSSL's reference-counted memory. This function does not increment the reference count for the `X509`
    /// object here, nor does it duplicate it: it just takes ownership of the copy here. This object
    /// **will** deallocate the underlying `X509` object when deinited, and so if you need to keep that
    /// `X509` object alive you should call `X509_dup` before passing the pointer here.
    ///
    /// In general, however, this function should be avoided in favour of one of the convenience
    /// initializers, which ensure that the lifetime of the `X509` object is better-managed.
    static public func fromUnsafePointer(takingOwnership pointer: UnsafeMutablePointer<X509>) -> OpenSSLCertificate {
        return OpenSSLCertificate(withReference: pointer)
    }

    /// Get a sequence of the alternative names in the certificate.
    internal func subjectAlternativeNames() -> SubjectAltNameSequence? {
        guard let sanExtension = CNIOBoringSSL_X509_get_ext_d2i(self.ref, NID_subject_alt_name, nil, nil) else {
            return nil
        }
        return SubjectAltNameSequence(nameStack: OpaquePointer(sanExtension))
    }

    /// Returns the commonName field in the Subject of this certificate.
    ///
    /// It is technically possible to have multiple common names in a certificate. As the primary
    /// purpose of this field in SwiftNIO is to validate TLS certificates, we only ever return
    /// the *most significant* (i.e. last) instance of commonName in the subject.
    internal func commonName() -> [UInt8]? {
        // No subject name is unexpected, but it gives us an easy time of handling this at least.
        guard let subjectName = CNIOBoringSSL_X509_get_subject_name(self.ref) else {
            return nil
        }

        // Per the man page, to find the first entry we set lastIndex to -1. When there are no
        // more entries, -1 is returned as the index of the next entry.
        var lastIndex: Int32 = -1
        var nextIndex: Int32 = -1
        repeat {
            lastIndex = nextIndex
            nextIndex = CNIOBoringSSL_X509_NAME_get_index_by_NID(subjectName, NID_commonName, lastIndex)
        } while nextIndex >= 0

        // It's totally allowed to have no commonName.
        guard lastIndex >= 0 else {
            return nil
        }

        // This is very unlikely, but it could happen.
        guard let nameData = CNIOBoringSSL_X509_NAME_ENTRY_get_data(CNIOBoringSSL_X509_NAME_get_entry(subjectName, lastIndex)) else {
            return nil
        }

        // Cool, we have the name. Let's have OpenSSL give it to us in UTF-8 form and then put those bytes
        // into our own array.
        var encodedName: UnsafeMutablePointer<UInt8>? = nil
        let stringLength = CNIOBoringSSL_ASN1_STRING_to_UTF8(&encodedName, nameData)

        guard let namePtr = encodedName else {
            return nil
        }

        let arr = [UInt8](UnsafeBufferPointer(start: namePtr, count: Int(stringLength)))
        CNIOBoringSSL_OPENSSL_free(namePtr)
        return arr
    }

    deinit {
        CNIOBoringSSL_X509_free(ref)
    }
}

// MARK:- Utility Functions
// We don't really want to get too far down the road of providing helpers for things like certificates
// and private keys: this is really the domain of alternative cryptography libraries. However, to
// enable users of swift-nio-ssl to use other cryptography libraries it will be helpful to provide
// the ability to obtain the bytes that correspond to certificates and keys.
extension OpenSSLCertificate {
    /// Obtain the public key for this `OpenSSLCertificate`.
    ///
    /// - returns: This certificate's `OpenSSLPublicKey`.
    /// - throws: If an error is encountered extracting the key.
    public func extractPublicKey() throws -> OpenSSLPublicKey {
        guard let key = CNIOBoringSSL_X509_get_pubkey(self.ref) else {
            throw NIOOpenSSLError.unableToAllocateOpenSSLObject
        }

        return OpenSSLPublicKey.fromInternalPointer(takingOwnership: key)
    }
}

extension OpenSSLCertificate: Equatable {
    public static func ==(lhs: OpenSSLCertificate, rhs: OpenSSLCertificate) -> Bool {
        return CNIOBoringSSL_X509_cmp(lhs.ref, rhs.ref) == 0
    }
}

/// A helper sequence object that enables us to represent subject alternative names
/// as an iterable Swift sequence.
internal class SubjectAltNameSequence: Sequence, IteratorProtocol {
    typealias Element = OpenSSLCertificate.AlternativeName

    private let nameStack: OpaquePointer
    private var nextIdx: Int
    private let stackSize: Int

    init(nameStack: OpaquePointer) {
        self.nameStack = nameStack
        self.stackSize = CNIOBoringSSLShims_sk_GENERAL_NAME_num(nameStack)
        self.nextIdx = 0
    }

    private func addressFromBytes(bytes: UnsafeBufferPointer<UInt8>) -> OpenSSLCertificate.IPAddress? {
        switch bytes.count {
        case 4:
            let addr = bytes.baseAddress?.withMemoryRebound(to: in_addr.self, capacity: 1) {
                return $0.pointee
            }
            guard let innerAddr = addr else {
                return nil
            }
            return .ipv4(innerAddr)
        case 16:
            let addr = bytes.baseAddress?.withMemoryRebound(to: in6_addr.self, capacity: 1) {
                return $0.pointee
            }
            guard let innerAddr = addr else {
                return nil
            }
            return .ipv6(innerAddr)
        default:
            return nil
        }
    }

    func next() -> OpenSSLCertificate.AlternativeName? {
        guard self.nextIdx < self.stackSize else {
            return nil
        }

        guard let name = CNIOBoringSSLShims_sk_GENERAL_NAME_value(self.nameStack, self.nextIdx) else {
            fatalError("Unexpected null pointer when unwrapping SAN value")
        }

        self.nextIdx += 1

        switch name.pointee.type {
        case GEN_DNS:
            let namePtr = UnsafeBufferPointer(start: CNIOBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                                              count: Int(CNIOBoringSSL_ASN1_STRING_length(name.pointee.d.ia5)))
            let nameString = [UInt8](namePtr)
            return .dnsName(nameString)
        case GEN_IPADD:
            let addrPtr = UnsafeBufferPointer(start: CNIOBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                                              count: Int(CNIOBoringSSL_ASN1_STRING_length(name.pointee.d.ia5)))
            guard let addr = addressFromBytes(bytes: addrPtr) else {
                // This should throw, but we can't throw from next(). Skip this instead.
                return self.next()
            }
            return .ipAddress(addr)
        default:
            // We don't recognise this name type. Skip it.
            return next()
        }
    }

    deinit {
        CNIOBoringSSL_GENERAL_NAMES_free(self.nameStack)
    }
}
