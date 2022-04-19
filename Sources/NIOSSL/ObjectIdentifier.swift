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

/// Object Identifier (OID)
public struct NIOSSLObjectIdentifier: Hashable {
    fileprivate final class Storage {
        
        /// All operations accessing `reference` need to be implemented while guaranteeing that the enclosing `self` has a reference count of at least one.
        /// Otherwise `reference` could already be freed. This would result in undefined behaviour as we access a dangling pointer.
        /// One way we can guarantee this is by implementation all operations as methods/computed properties on `Storage`.
        /// Swift guarantees that `self` is not deallocated during the execution of a method/computed property on `self`.
        private let reference: OpaquePointer
        
        fileprivate init?(_ string: String) {
            let result = string.withCString { string in
                // If no_name (the last parameter of CNIOBoringSSL_OBJ_txt2obj) is 0 then long names and
                // short names will be interpreted as well as numerical forms.
                // If no_name is 1 only the numerical form is acceptable.
                // source: https://www.openssl.org/docs/manmaster/man3/OBJ_txt2obj.html
                CNIOBoringSSL_OBJ_txt2obj(string, 1)
            }
            guard let reference = result else {
                return nil
            }
            self.reference = reference
        }
        
        fileprivate init(takingOwnershipOf reference: OpaquePointer) {
            self.reference = reference
        }
        
        deinit {
            CNIOBoringSSL_ASN1_OBJECT_free(reference)
        }
    }
    
    private let storage: Storage
    
    /// Creates a Object Identifier (OID) from its textual dotted representation (e.g. `1.2.3`)
    /// - Parameter string: textual dotted representation of an OID
    public init?(_ string: String) {
        guard let storage = Storage(string) else {
            return nil
        }
        self.storage = storage
    }
    
    /// Creates an Object Identifier (OID) from an OpenSSL reference.
    /// - Note: initialising an ``NIOSSLObjectIdentifier`` takes ownership of the reference and will free it after the reference count drops to zero
    /// - Parameter reference: reference to a valid OpenSSL OID aka OBJ
    internal init(takingOwnershipOf reference: OpaquePointer) {
        self.storage = Storage(takingOwnershipOf: reference)
    }
}

extension NIOSSLObjectIdentifier.Storage: Equatable {
    fileprivate static func == (lhs: NIOSSLObjectIdentifier.Storage, rhs: NIOSSLObjectIdentifier.Storage) -> Bool {
        CNIOBoringSSL_OBJ_cmp(lhs.reference, rhs.reference) == 0
    }
}

extension NIOSSLObjectIdentifier.Storage: Hashable {
    fileprivate func hash(into hasher: inout Hasher) {
        let length = CNIOBoringSSL_OBJ_length(self.reference)
        let data = CNIOBoringSSL_OBJ_get0_data(self.reference)
        let buffer = UnsafeRawBufferPointer(start: data, count: length)
        hasher.combine(bytes: buffer)
    }
}

extension NIOSSLObjectIdentifier.Storage: LosslessStringConvertible {
    fileprivate var description: String {
        var failed = false
        let oid = String(customUnsafeUninitializedCapacity: 80) { buffer in
            // OBJ_obj2txt() is awkward and messy to use: it doesn't follow the convention of other OpenSSL functions where the buffer can be set to NULL to determine the amount of data that should be written. Instead buf must point to a valid buffer and buf_len should be set to a positive value. A buffer length of 80 should be more than enough to handle any OID encountered in practice.
            // source: https://linux.die.net/man/3/obj_obj2txt
            let result = buffer.withMemoryRebound(to: CChar.self) { buffer in
                // If no_name (the last argument of CNIOBoringSSL_OBJ_obj2txt) is 0 then
                // if the object has a long or short name then that will be used,
                // otherwise the numerical form will be used.
                // If no_name is 1 then the numerical form will always be used.
                // source: https://www.openssl.org/docs/manmaster/man3/OBJ_obj2txt.html
                CNIOBoringSSL_OBJ_obj2txt(buffer.baseAddress, Int32(buffer.count), self.reference, 1)
            }
            guard result >= 0 else {
                // result of -1 indicates an error
                failed = true
                return 0
            }
            return Int(result)
        }
        guard !failed else {
            return "failed to convert OID to string"
        }
        return oid
    }
}

extension NIOSSLObjectIdentifier: LosslessStringConvertible {
    public var description: String {
        self.storage.description
    }
}
