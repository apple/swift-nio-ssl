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

/// A representation of an ASN.1 Object Identifier (OID)
public struct NIOSSLObjectIdentifier {
    private enum Storage {
        final class Deallocator {
            var reference: OpaquePointer!

            init(takeOwnershipOf reference: OpaquePointer!) {
                self.reference = reference
            }

            deinit {
                CNIOBoringSSL_ASN1_OBJECT_free(self.reference)
            }
        }

        case owned(Deallocator)
        case borrowed(reference: OpaquePointer!, owner: AnyObject)

        init(takeOwnershipOf reference: OpaquePointer!) {
            self = .owned(.init(takeOwnershipOf: reference))
        }

        init(borrowing reference: OpaquePointer!, owner: AnyObject) {
            self = .borrowed(reference: reference, owner: owner)
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
                case .borrowed(let reference, _):
                    return try body(reference)
                }
            }
        }
    }

    private let storage: Storage

    /// Creates a Object Identifier (OID) from its textual dotted representation (e.g. `1.2.3`)
    ///
    /// - Parameter string: textual dotted representation of an OID
    public init?(_ string: String) {
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
        self.storage = .init(takeOwnershipOf: reference)
    }

    /// Creates an Object Identifier (OID) from an OpenSSL reference.
    ///
    /// - Note: initialising an ``NIOSSLObjectIdentifier`` takes ownership of the reference and will free it after the reference count drops to zero
    /// - Parameter reference: reference to a valid OpenSSL OID aka OBJ
    internal init(takingOwnershipOf reference: OpaquePointer!) {
        self.storage = .init(takeOwnershipOf: reference)
    }

    /// Creates an Object Identifier (OID) from an OpenSSL reference.
    /// - Note: initialising an ``NIOSSLObjectIdentifier`` with *this* constructor does **not** take ownership of the memory. Instead ``NIOSSLObjectIdentifier`` keeps a reference to the owning object which it will retain for the lifetime of itself.
    /// - Parameters
    ///   - reference: reference to a valid OpenSSL OID aka OBJ
    ///   - owner: owner of the memory `reference` is pointing to which it will retain.
    internal init(borrowing reference: OpaquePointer!, owner: AnyObject) {
        self.storage = .init(borrowing: reference, owner: owner)
    }

    /// Creates a copy of an Object Identifier (OID) from an OpenSSL reference
    /// - Parameter reference: reference to a valid OpenSSL OID aka OBJ
    internal init(copyOf reference: OpaquePointer!) {
        self.init(takingOwnershipOf: CNIOBoringSSL_OBJ_dup(reference))
    }
}

// NIOSSLObjectIdentifier is immutable and therefore Sendable
extension NIOSSLObjectIdentifier: @unchecked Sendable {}

extension NIOSSLObjectIdentifier: Equatable {
    public static func == (lhs: NIOSSLObjectIdentifier, rhs: NIOSSLObjectIdentifier) -> Bool {
        lhs.storage.withReference { lhsReference in
            rhs.storage.withReference { rhsReference in
                CNIOBoringSSL_OBJ_cmp(lhsReference, rhsReference) == 0
            }
        }
    }
}

extension NIOSSLObjectIdentifier: Hashable {
    public func hash(into hasher: inout Hasher) {
        self.storage.withReference { reference in
            let length = CNIOBoringSSL_OBJ_length(reference)
            let data = CNIOBoringSSL_OBJ_get0_data(reference)
            let buffer = UnsafeRawBufferPointer(start: data, count: length)
            hasher.combine(bytes: buffer)
        }
    }
}

extension NIOSSLObjectIdentifier: LosslessStringConvertible {
    public var description: String {
        self.storage.withReference { reference in
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
                    CNIOBoringSSL_OBJ_obj2txt(buffer.baseAddress, Int32(buffer.count), reference, 1)
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
}
