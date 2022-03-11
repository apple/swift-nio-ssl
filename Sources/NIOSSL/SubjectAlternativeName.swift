//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
@_implementationOnly import CNIOBoringSSLShims

#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
import Darwin.C
#elseif os(Linux) || os(FreeBSD) || os(Android)
import Glibc
#else
#error("unsupported os")
#endif

/// Collection of all Subject Alternative Names from a `NIOSSLCertificate`
public struct _SubjectAlternativeNames {
    
    @usableFromInline
    internal final class Storage {
        
        fileprivate let nameStack: OpaquePointer
        @usableFromInline internal let stackSize: Int

        internal init(nameStack: OpaquePointer) {
            self.nameStack = nameStack
            self.stackSize = CNIOBoringSSLShims_sk_GENERAL_NAME_num(nameStack)
        }
        
        public subscript(position: Int) -> Element {
            guard let name = CNIOBoringSSLShims_sk_GENERAL_NAME_value(self.nameStack, position) else {
                fatalError("Unexpected null pointer when unwrapping SAN value")
            }
            
            let contents = UnsafeBufferPointer(
                start: CNIOBoringSSL_ASN1_STRING_get0_data(name.pointee.d.ia5),
                count: Int(CNIOBoringSSL_ASN1_STRING_length(name.pointee.d.ia5))
            )
            return .init(nameType: .init(name.pointee.type), contents: .init(collection: self, buffer: contents))
        }

        deinit {
            CNIOBoringSSL_GENERAL_NAMES_free(self.nameStack)
        }
    }
    
    
    @usableFromInline internal var storage: Storage
    
    internal init(nameStack: OpaquePointer) {
        self.storage = .init(nameStack: nameStack)
    }
}

extension _SubjectAlternativeNames: RandomAccessCollection {
    
    @inlinable public subscript(position: Int) -> _SubjectAlternativeName {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return self.storage[position]
    }
    
    @inlinable public var startIndex: Int { 0 }
    @inlinable public var endIndex: Int { self.storage.stackSize }
}

public struct _SubjectAlternativeName {
    
    public struct NameType: Hashable {
        public var rawValue: Int

        public init(_ rawCode: Int) {
            self.rawValue = rawCode
        }

        fileprivate init(_ rawCode: Int32) {
            self.init(Int(rawCode))
        }
        
        public static let email = Self(GEN_EMAIL)
        public static let dnsName = Self(GEN_DNS)
        public static let ipAddress = Self(GEN_IPADD)
        public static let uri = Self(GEN_URI)
    }

    public struct Contents {
        // only part of this type to keep a strong reference to the underlying storage of `buffer`
        private let collection: _SubjectAlternativeNames.Storage
        // lifetime automatically managed by `collection`
        @usableFromInline internal let buffer: UnsafeBufferPointer<UInt8>
        
        internal init(collection: _SubjectAlternativeNames.Storage, buffer: UnsafeBufferPointer<UInt8>) {
            self.collection = collection
            self.buffer = buffer
        }
        
        @inlinable public func withUnsafeBufferPointer<Result>(
            _ body: (UnsafeBufferPointer<UInt8>) throws -> Result
        ) rethrows -> Result {
            try body(self.buffer)
        }
    }
    
    // should be replaced by `swift-nio`s `IPAddress` once https://github.com/apple/swift-nio/issues/1650 is resolved
    internal enum IPAddress {
        case ipv4(in_addr)
        case ipv6(in6_addr)
    }
    
    public var nameType: NameType
    public var contents: Contents
}

extension _SubjectAlternativeName.Contents: RandomAccessCollection {
    
    @inlinable public var startIndex: Int { self.buffer.startIndex }
    @inlinable public var endIndex: Int { self.buffer.endIndex }
    
    @inlinable public subscript(position: Int) -> UInt8 {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return self.buffer[position]
    }
}

extension _SubjectAlternativeName.IPAddress {
    
    internal init?(_ subjectAlternativeName: _SubjectAlternativeName) {
        guard subjectAlternativeName.nameType == .ipAddress else {
            return nil
        }
        switch subjectAlternativeName.contents.count {
        case 4:
            let addr = subjectAlternativeName.contents.withUnsafeBufferPointer {
                $0.baseAddress.map {
                    UnsafeRawPointer($0).load(as: in_addr.self)
                }
            }
            guard let innerAddr = addr else {
                return nil
            }
            self = .ipv4(innerAddr)
        case 16:
            let addr = subjectAlternativeName.contents.withUnsafeBufferPointer {
                $0.baseAddress.map {
                    UnsafeRawPointer($0).load(as: in6_addr.self)
                }
            }
            guard let innerAddr = addr else {
                return nil
            }
            self = .ipv6(innerAddr)
        default:
            return nil
        }
    }
}

extension _SubjectAlternativeName.IPAddress: CustomStringConvertible {
    
    private static let ipv4AddressLength = 16
    private static let ipv6AddressLength = 46
    
    /// A string representation of the IP address.
    /// E.g. IPv4: `192.168.0.1`
    /// E.g. IPv6: `2001:db8::1`
    public var description: String {
        switch self {
        case .ipv4(let addr):
            return Self.ipv4ToString(addr)
        case .ipv6(let addr):
            return Self.ipv6ToString(addr)
        }
    }
    
    static private func ipv4ToString(_ address: in_addr) -> String {
        
        var address = address
        var dest: [CChar] = Array(repeating: 0, count: Self.ipv4AddressLength)
        dest.withUnsafeMutableBufferPointer { pointer in
            let result = inet_ntop(AF_INET, &address, pointer.baseAddress!, socklen_t(pointer.count))
            precondition(result != nil, "The IP address was invalid. This should never happen as we're within the IP address struct.")
        }
        return String(cString: &dest)
    }
    
    static private func ipv6ToString(_ address: in6_addr) -> String {
        var address = address
        var dest: [CChar] = Array(repeating: 0, count: Self.ipv6AddressLength)
        dest.withUnsafeMutableBufferPointer { pointer in
            let result = inet_ntop(AF_INET6, &address, pointer.baseAddress!, socklen_t(pointer.count))
            precondition(result != nil, "The IP address was invalid. This should never happen as we're within the IP address struct.")
        }
        return String(cString: &dest)
    }
}
