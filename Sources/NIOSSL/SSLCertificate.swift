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
@_implementationOnly import CNIOBoringSSLShims
#else
import CNIOBoringSSL
import CNIOBoringSSLShims
#endif
import NIO

/// A reference to a BoringSSL Certificate object (`X509 *`).
///
/// This thin wrapper class allows us to use ARC to automatically manage
/// the memory associated with this TLS certificate. That ensures that BoringSSL
/// will not free the underlying buffer until we are done with the certificate.
///
/// This class also provides several convenience constructors that allow users
/// to obtain an in-memory representation of a TLS certificate from a buffer of
/// bytes or from a file path.
public class NIOSSLCertificate {
    internal let _ref: UnsafeMutableRawPointer/*<X509>*/

    internal var ref: UnsafeMutablePointer<X509> {
        return self._ref.assumingMemoryBound(to: X509.self)
    }

    internal enum AlternativeName {
        case dnsName([UInt8])
        case ipAddress(IPAddress)
    }

    internal enum IPAddress {
        case ipv4(in_addr)
        case ipv6(in6_addr)
    }
    
    public var serialNumber: [UInt8] {
        let serialNumber = CNIOBoringSSL_X509_get_serialNumber(self.ref)!
        return Array(UnsafeBufferPointer(start: serialNumber.pointee.data, count: Int(serialNumber.pointee.length)))
    }

    private init(withOwnedReference ref: UnsafeMutablePointer<X509>) {
        self._ref = UnsafeMutableRawPointer(ref) // erasing the type for @_implementationOnly import CNIOBoringSSL
    }

    /// Create a NIOSSLCertificate from a file at a given path in either PEM or
    /// DER format.
    ///
    /// Note that this method will only ever load the first certificate from a given file.
    public convenience init(file: String, format: NIOSSLSerializationFormats) throws {
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
            throw NIOSSLError.failedToLoadCertificate
        }

        self.init(withOwnedReference: x509!)
    }

    /// Create a NIOSSLCertificate from a buffer of bytes in either PEM or
    /// DER format.
    ///
    /// - SeeAlso: `NIOSSLCertificate.init(bytes:format:)`
    @available(*, deprecated, renamed: "NIOSSLCertificate.init(bytes:format:)")
    public convenience init(buffer: [Int8], format: NIOSSLSerializationFormats) throws  {
        try self.init(bytes: buffer.map(UInt8.init), format: format)
    }

    /// Create a NIOSSLCertificate from a buffer of bytes in either PEM or
    /// DER format.
    public convenience init(bytes: [UInt8], format: NIOSSLSerializationFormats) throws {
        let ref = bytes.withUnsafeBytes { (ptr) -> UnsafeMutablePointer<X509>? in
            let bio = CNIOBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

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
            throw NIOSSLError.failedToLoadCertificate
        }

        self.init(withOwnedReference: ref!)
    }

    /// Create a NIOSSLCertificate from a buffer of bytes in either PEM or DER format.
    internal convenience init(bytes ptr: UnsafeRawBufferPointer, format: NIOSSLSerializationFormats) throws {
        // TODO(cory):
        // The body of this method is exactly identical to the initializer above, except for the "withUnsafeBytes" call.
        // ContiguousBytes would have been the lowest effort way to reduce this duplication, but we can't use it without
        // bringing Foundation in. Probably we should use Sequence where Element == UInt8 and the withUnsafeContiguousBytesIfAvailable
        // method, but that's a much more substantial refactor. Let's do it later.
        let bio = CNIOBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!

        defer {
            CNIOBoringSSL_BIO_free(bio)
        }

        let ref: UnsafeMutablePointer<X509>?

        switch format {
        case .pem:
            ref = CNIOBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        case .der:
            ref = CNIOBoringSSL_d2i_X509_bio(bio, nil)
        }

        if ref == nil {
            throw NIOSSLError.failedToLoadCertificate
        }

        self.init(withOwnedReference: ref!)
    }

    /// Create a NIOSSLCertificate wrapping a pointer into BoringSSL.
    ///
    /// This is a function that should be avoided as much as possible because it plays poorly with
    /// BoringSSL's reference-counted memory. This function does not increment the reference count for the `X509`
    /// object here, nor does it duplicate it: it just takes ownership of the copy here. This object
    /// **will** deallocate the underlying `X509` object when deinited, and so if you need to keep that
    /// `X509` object alive you should call `X509_dup` before passing the pointer here.
    ///
    /// In general, however, this function should be avoided in favour of one of the convenience
    /// initializers, which ensure that the lifetime of the `X509` object is better-managed.
    static func fromUnsafePointer(takingOwnership pointer: UnsafeMutablePointer<X509>) -> NIOSSLCertificate {
        return NIOSSLCertificate(withOwnedReference: pointer)
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
        var lastIndex: CInt = -1
        var nextIndex: CInt = -1
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

        // Cool, we have the name. Let's have BoringSSL give it to us in UTF-8 form and then put those bytes
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
extension NIOSSLCertificate {
    /// Obtain the public key for this `NIOSSLCertificate`.
    ///
    /// - returns: This certificate's `NIOSSLPublicKey`.
    /// - throws: If an error is encountered extracting the key.
    public func extractPublicKey() throws -> NIOSSLPublicKey {
        guard let key = CNIOBoringSSL_X509_get_pubkey(self.ref) else {
            fatalError("Failed to extract a public key reference")
        }

        return NIOSSLPublicKey.fromInternalPointer(takingOwnership: key)
    }

    /// Extracts the bytes of this certificate in DER format.
    ///
    /// - returns: The DER-encoded bytes for this certificate.
    /// - throws: If an error occurred while serializing the certificate.
    public func toDERBytes() throws -> [UInt8] {
        return try self.withUnsafeDERCertificateBuffer { Array($0) }
    }

    /// Create an array of `NIOSSLCertificate`s from a buffer of bytes in PEM format.
    ///
    /// - Parameter buffer: The PEM buffer to read certificates from.
    /// - Throws: If an error is encountered while reading certificates.
    /// - SeeAlso: `NIOSSLCertificate.fromPEMBytes(_:)`
    @available(*, deprecated, renamed: "NIOSSLCertificate.fromPEMBytes(_:)")
    public class func fromPEMBuffer(_ buffer: [Int8]) throws -> [NIOSSLCertificate] {
        return try fromPEMBytes(buffer.map(UInt8.init))
    }

    /// Create an array of `NIOSSLCertificate`s from a buffer of bytes in PEM format.
    ///
    /// - Parameter bytes: The PEM buffer to read certificates from.
    /// - Throws: If an error is encountered while reading certificates.
    public class func fromPEMBytes(_ bytes: [UInt8]) throws -> [NIOSSLCertificate] {
        CNIOBoringSSL_ERR_clear_error()
        defer {
            CNIOBoringSSL_ERR_clear_error()
        }

        return try bytes.withUnsafeBytes { (ptr) -> [NIOSSLCertificate] in
            let bio = CNIOBoringSSL_BIO_new_mem_buf(ptr.baseAddress, CInt(ptr.count))!
            defer {
                CNIOBoringSSL_BIO_free(bio)
            }

            return try readCertificatesFromBIO(bio)
        }
    }

    /// Create an array of `NIOSSLCertificate`s from a file at a given path in PEM format.
    ///
    /// - Parameter file: The PEM file to read certificates from.
    /// - Throws: If an error is encountered while reading certificates.
    public class func fromPEMFile(_ path: String) throws -> [NIOSSLCertificate] {
        CNIOBoringSSL_ERR_clear_error()
        defer {
            CNIOBoringSSL_ERR_clear_error()
        }

        guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_file()) else {
            fatalError("Failed to create a BIO handle to read a PEM file")
        }
        defer {
            CNIOBoringSSL_BIO_free(bio)
        }

        guard CNIOBoringSSL_BIO_read_filename(bio, path) > 0 else {
            throw NIOSSLError.failedToLoadCertificate
        }

        return try readCertificatesFromBIO(bio)
    }

    /// Reads `NIOSSLCertificate`s from the given BIO.
    private class func readCertificatesFromBIO(_ bio: UnsafeMutablePointer<BIO>) throws -> [NIOSSLCertificate] {
        guard let x509 = CNIOBoringSSL_PEM_read_bio_X509_AUX(bio, nil, nil, nil) else {
            throw NIOSSLError.failedToLoadCertificate
        }

        var certificates = [NIOSSLCertificate(withOwnedReference: x509)]

        while let x = CNIOBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil) {
            certificates.append(.init(withOwnedReference: x))
        }

        let err = CNIOBoringSSL_ERR_peek_error()

        // If we hit the end of the file then it's not a real error, we just read as much as we could.
        if CNIOBoringSSLShims_ERR_GET_LIB(err) == ERR_LIB_PEM && CNIOBoringSSLShims_ERR_GET_REASON(err) == PEM_R_NO_START_LINE {
            CNIOBoringSSL_ERR_clear_error()
        } else {
            throw NIOSSLError.failedToLoadCertificate
        }

        return certificates
    }

    /// Calls the given body function with a temporary buffer containing the DER-encoded bytes of this
    /// certificate. This function does allocate for these bytes, but there is no way to avoid doing so with the
    /// X509 API in BoringSSL.
    ///
    /// The pointer provided to the closure is not valid beyond the lifetime of this method call.
    private func withUnsafeDERCertificateBuffer<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
            fatalError("Failed to malloc for a BIO handler")
        }

        defer {
            CNIOBoringSSL_BIO_free(bio)
        }

        let rc = CNIOBoringSSL_i2d_X509_bio(bio, self.ref)
        guard rc == 1 else {
            let errorStack = BoringSSLError.buildErrorStack()
            throw BoringSSLError.unknownError(errorStack)
        }

        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            fatalError("Failed to map bytes from a certificate")
        }

        return try body(bytes)
    }
}

extension NIOSSLCertificate: Equatable {
    public static func ==(lhs: NIOSSLCertificate, rhs: NIOSSLCertificate) -> Bool {
        return CNIOBoringSSL_X509_cmp(lhs.ref, rhs.ref) == 0
    }
}


extension NIOSSLCertificate: Hashable {
    public func hash(into hasher: inout Hasher) {
        // We just hash the DER bytes of the cert. If we can't get the bytes, this is a fatal error as
        // we have no way to recover from it. It's unfortunate that this allocates, but the code to hash
        // a certificate in any other way is too fragile to justify.
        try! self.withUnsafeDERCertificateBuffer { hasher.combine(bytes: $0) }
    }
}

/// A helper sequence object that enables us to represent subject alternative names
/// as an iterable Swift sequence.
internal class SubjectAltNameSequence: Sequence, IteratorProtocol {
    typealias Element = NIOSSLCertificate.AlternativeName

    private let nameStack: OpaquePointer
    private var nextIdx: Int
    private let stackSize: Int

    init(nameStack: OpaquePointer) {
        self.nameStack = nameStack
        self.stackSize = CNIOBoringSSLShims_sk_GENERAL_NAME_num(nameStack)
        self.nextIdx = 0
    }

    private func addressFromBytes(bytes: UnsafeBufferPointer<UInt8>) -> NIOSSLCertificate.IPAddress? {
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

    func next() -> NIOSSLCertificate.AlternativeName? {
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

extension NIOSSLCertificate: CustomStringConvertible {
    
    public var description: String {
        let serialNumber = self.serialNumber.map { String($0, radix: 16) }.reduce("", +)
        var desc = "<NIOSSLCertificate;serial_number=\(serialNumber)"
        if let commonNameBytes = self.commonName() {
            let commonName = String(decoding: commonNameBytes, as: UTF8.self)
            desc += ";common_name=" + commonName
        }
        if let alternativeName = self.subjectAlternativeNames() {
            let altNames = alternativeName.map { name in
                switch name {
                case .dnsName(let bytes):
                    return String(decoding: bytes, as: UTF8.self)
                case .ipAddress(let address):
                    return String(describing: address)
                }
            }.joined(separator: ",")
            desc += ";alternative_names=\(altNames)"
        }
        return desc + ">"
    }
    
}

extension NIOSSLCertificate.IPAddress: CustomStringConvertible {
    
    private static let ipv4AddressLength = 16
    private static let ipv6AddressLength = 46
    
    /// A string representation of the IP address.
    /// E.g. IPv4: `192.168.0.1`
    /// E.g. IPv6: `2001:db8::1`
    public var description: String {
        switch self {
        case .ipv4(let addr):
            return self.ipv4ToString(addr)
        case .ipv6(let addr):
            return self.ipv6ToString(addr)
        }
    }
    
    private func ipv4ToString(_ address: in_addr) -> String {
        var address = address
        var dest: [CChar] = Array(repeating: 0, count: NIOSSLCertificate.IPAddress.ipv4AddressLength)
        dest.withUnsafeMutableBufferPointer { pointer in
            let result = inet_ntop(AF_INET, &address, pointer.baseAddress!, socklen_t(pointer.count))
            precondition(result != nil, "The IP address was invalid. This should never happen as we're within the IP address struct.")
        }
        return String(cString: &dest)
    }
    
    private func ipv6ToString(_ address: in6_addr) -> String {
        var address = address
        var dest: [CChar] = Array(repeating: 0, count: NIOSSLCertificate.IPAddress.ipv6AddressLength)
        dest.withUnsafeMutableBufferPointer { pointer in
            let result = inet_ntop(AF_INET6, &address, pointer.baseAddress!, socklen_t(pointer.count))
            precondition(result != nil, "The IP address was invalid. This should never happen as we're within the IP address struct.")
        }
        return String(cString: &dest)
    }
    
}
