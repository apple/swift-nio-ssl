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

public struct _SSLCertificateExtensions {
    enum Storage {
        final class Deallocator {
            var reference: OpaquePointer!
            
            init(takeOwnershipOf reference: OpaquePointer!) {
                self.reference = reference
            }
            
            deinit {
                CNIOBoringSSL_sk_X509_EXTENSION_free(self.reference)
            }
        }
        
        case owned(Deallocator)
        case unowned(reference: OpaquePointer!, owner: AnyObject)
        
        init(takeOwnershipOf reference: OpaquePointer!) {
            self = .owned(.init(takeOwnershipOf: reference))
        }
        
        init(takeUnowned reference: OpaquePointer!, owner: AnyObject) {
            self = .unowned(reference: reference, owner: owner)
        }
        
        /// The owner of the memory to which the reference points
        var owner: AnyObject {
            switch self {
            case .owned(let deallocator):
                return deallocator
            case .unowned(_, let owner):
                return owner
            }
        }
        
        /// All operations accessing `reference` need to be implemented while guaranteeing that we still have a reference to the memory owner.
        /// Otherwise `reference` could already be freed. This would result in undefined behaviour as we access a dangling pointer.
        /// This method guarantees that `reference` is valid during execution of `body`.
        internal func withReference<Result>(
            _ body: (OpaquePointer?) throws -> Result
        ) rethrows -> Result {
            try withExtendedLifetime(self) {
                switch self {
                case .owned(let deallocator):
                    return try body(deallocator.reference)
                case .unowned(let reference, _):
                    return try body(reference)
                }
            }
        }
    }
    
    @usableFromInline internal let stackSize: Int
    internal let storage: Storage
    
    internal init(takeOwnershipOf reference: OpaquePointer!) {
        self.storage = .init(takeOwnershipOf: reference)
        self.stackSize = CNIOBoringSSL_sk_X509_EXTENSION_num(reference)
    }
    
    internal init(takeUnowned reference: OpaquePointer!, owner: AnyObject) {
        self.storage = .init(takeUnowned: reference, owner: owner)
        self.stackSize = CNIOBoringSSL_sk_X509_EXTENSION_num(reference)
    }
    
    internal init(copyOf reference: OpaquePointer!) {
        self.init(takeOwnershipOf: CNIOBoringSSL_sk_X509_EXTENSION_dup(reference))
    }
    
    internal init() {
        self.init(takeOwnershipOf: nil)
    }
    
    
}

extension NIOSSLCertificate {
    public var _extensions: _SSLCertificateExtensions {
        _SSLCertificateExtensions(takeUnowned: CNIOBoringSSL_X509_get0_extensions(self._ref), owner: self)
    }
}

extension _SSLCertificateExtensions: RandomAccessCollection {
    public subscript(position: Int) -> _SSLCertificateExtension {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return self.storage.withReference { reference in
            guard let value = CNIOBoringSSLShims_sk_X509_EXTENSION_value(reference, position) else {
                fatalError("unexpected null pointer when unwrapping extension value at \(position)")
            }
            
            return .init(value: value, owner: self.storage.owner)
        }
    }
    
    @inlinable public var startIndex: Int { 0 }
    @inlinable public var endIndex: Int { self.stackSize }
}

public struct _SSLCertificateExtension {
    internal init(value: OpaquePointer, owner: AnyObject) {
        self.owner = owner
        self.value = value
    }
    
    /// only part of this type to keep a strong reference to the underlying storage of `value`
    private let owner: AnyObject
    /// lifetime automatically managed by `collection`
    internal let value: OpaquePointer
    
    public var objectIdentifier: NIOSSLObjectIdentifier {
        .init(takeUnowned: CNIOBoringSSL_X509_EXTENSION_get_object(value), owner: owner)
    }
    
    public var isCritical: Bool {
        CNIOBoringSSL_X509_EXTENSION_get_critical(value) == 1
    }
    
    public var data: Data {
        let data = CNIOBoringSSL_X509_EXTENSION_get_data(value)
        let buffer = UnsafeBufferPointer(
            start: CNIOBoringSSL_ASN1_STRING_get0_data(data),
            count: Int(CNIOBoringSSL_ASN1_STRING_length(data))
        )
        return .init(buffer: buffer, owner: owner)
    }
}

extension _SSLCertificateExtension {
    public struct Data {
        // only part of this type to keep a strong reference to the underlying storage of `buffer`
        private let owner: AnyObject
        // lifetime automatically managed by `collection`
        @usableFromInline internal let buffer: UnsafeBufferPointer<UInt8>
        
        internal init(buffer: UnsafeBufferPointer<UInt8>, owner: AnyObject) {
            self.buffer = buffer
            self.owner = owner
        }
        
        @inlinable public func withUnsafeBufferPointer<Result>(
            _ body: (UnsafeBufferPointer<UInt8>) throws -> Result
        ) rethrows -> Result {
            try withExtendedLifetime(self) {
                try body(self.buffer)
            }
        }
    }
}

extension _SSLCertificateExtension.Data: RandomAccessCollection {
    @inlinable public var startIndex: Int { self.buffer.startIndex }
    @inlinable public var endIndex: Int { self.buffer.endIndex }
    
    @inlinable public subscript(position: Int) -> UInt8 {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return withUnsafeBufferPointer { $0[position] }
    }
    
   @inlinable public func withContiguousStorageIfAvailable<Result>(
    _ body: (UnsafeBufferPointer<UInt8>
    ) throws -> Result) rethrows -> Result? {
        try withUnsafeBufferPointer(body)
    }
}
