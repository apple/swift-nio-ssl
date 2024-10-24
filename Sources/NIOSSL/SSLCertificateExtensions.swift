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

extension NIOSSLCertificate {
    public struct _Extensions {
        private enum Storage {
            final class Deallocator {
                /// `reference` is optional because `CNIOBoringSSL_X509_get0_extensions` can return`nil` if no extensions are present.
                /// We therefore need to handle the `nil` case as if this collection is empty.
                let reference: OpaquePointer?

                init(takeOwnershipOf reference: OpaquePointer?) {
                    self.reference = reference
                }

                deinit {
                    if let reference = self.reference {
                        CNIOBoringSSL_sk_X509_EXTENSION_free(reference)
                    }
                }
            }

            case owned(Deallocator)
            /// `reference` is optional because `CNIOBoringSSL_X509_get0_extensions` can return`nil` if no extensions are present.
            /// We therefore need to handle the `nil` case as if this collection is empty.
            case borrowed(reference: OpaquePointer?, owner: AnyObject)

            init(takeOwnershipOf reference: OpaquePointer?) {
                self = .owned(.init(takeOwnershipOf: reference))
            }

            init(borrowing reference: OpaquePointer?, owner: AnyObject) {
                self = .borrowed(reference: reference, owner: owner)
            }

            /// The owner of the memory to which the reference points
            var owner: AnyObject {
                switch self {
                case .owned(let deallocator):
                    return deallocator
                case .borrowed(_, let owner):
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
                    case .borrowed(let reference, _):
                        return try body(reference)
                    }
                }
            }
        }

        @usableFromInline internal let stackSize: Int
        private let storage: Storage

        internal init(takeOwnershipOf reference: OpaquePointer?) {
            self.storage = .init(takeOwnershipOf: reference)
            if let reference = reference {
                self.stackSize = CNIOBoringSSL_sk_X509_EXTENSION_num(reference)
            } else {
                self.stackSize = 0
            }
        }

        internal init(borrowing reference: OpaquePointer?, owner: AnyObject) {
            self.storage = .init(borrowing: reference, owner: owner)
            if let reference = reference {
                self.stackSize = CNIOBoringSSL_sk_X509_EXTENSION_num(reference)
            } else {
                self.stackSize = 0
            }
        }
    }
}

// NIOSSLCertificate._Extensions is immutable and therefore Sendable
extension NIOSSLCertificate._Extensions: @unchecked Sendable {}

extension NIOSSLCertificate {
    public var _extensions: NIOSSLCertificate._Extensions {
        NIOSSLCertificate._Extensions(borrowing: CNIOBoringSSL_X509_get0_extensions(self._ref), owner: self)
    }
}

extension NIOSSLCertificate._Extensions: RandomAccessCollection {
    public subscript(position: Int) -> NIOSSLCertificate._Extension {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return self.storage.withReference { reference in
            let value = CNIOBoringSSLShims_sk_X509_EXTENSION_value(reference!, position)!
            return .init(borrowing: value, owner: self.storage.owner)
        }
    }

    @inlinable public var startIndex: Int { 0 }
    @inlinable public var endIndex: Int { self.stackSize }
}

extension NIOSSLCertificate {
    public struct _Extension {
        init(borrowing reference: OpaquePointer, owner: AnyObject) {
            self.owner = owner
            self._reference = reference
        }

        /// lifetime automatically managed by `owner`
        private let _reference: OpaquePointer

        /// only part of this type to keep a strong reference to the underlying storage of `reference`
        private let owner: AnyObject

        /// All operations accessing `reference` need to be implemented while guaranteeing that we still have a reference to the memory `owner`.
        /// Otherwise `reference` could already be freed. This would result in undefined behaviour as we access a dangling pointer.
        /// This method guarantees that `reference` is valid during execution of `body`.
        func withReference<Result>(
            _ body: (OpaquePointer?) throws -> Result
        ) rethrows -> Result {
            try withExtendedLifetime(owner) {
                try body(self._reference)
            }
        }

        public var objectIdentifier: NIOSSLObjectIdentifier {
            withReference {
                .init(borrowing: CNIOBoringSSL_X509_EXTENSION_get_object($0), owner: self.owner)
            }
        }

        public var isCritical: Bool {
            withReference {
                CNIOBoringSSL_X509_EXTENSION_get_critical($0) == 1
            }
        }

        public var data: Data {
            withReference {
                let data = CNIOBoringSSL_X509_EXTENSION_get_data($0)
                let buffer = UnsafeBufferPointer(
                    start: CNIOBoringSSL_ASN1_STRING_get0_data(data),
                    count: Int(CNIOBoringSSL_ASN1_STRING_length(data))
                )
                return .init(buffer: buffer, owner: self.owner)
            }
        }
    }
}

// NIOSSLCertificate._Extension is immutable and therefore Sendable
extension NIOSSLCertificate._Extension: @unchecked Sendable {}

extension NIOSSLCertificate._Extension {
    public struct Data {
        // only part of this type to keep a strong reference to the underlying storage of `buffer`
        private let owner: AnyObject
        // lifetime automatically managed by `owner`
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
        @inlinable public func withUnsafeBytes<Result>(
            _ body: (UnsafeRawBufferPointer) throws -> Result
        ) rethrows -> Result {
            try withExtendedLifetime(self) {
                try body(.init(self.buffer))
            }
        }
    }
}

// NIOSSLCertificate._Extension.Data is immutable and therefore Sendable
extension NIOSSLCertificate._Extension.Data: @unchecked Sendable {}

extension NIOSSLCertificate._Extension.Data: RandomAccessCollection {
    @inlinable public var startIndex: Int { self.buffer.startIndex }
    @inlinable public var endIndex: Int { self.buffer.endIndex }

    @inlinable public subscript(position: Int) -> UInt8 {
        precondition(self.indices.contains(position), "index \(position) out of bounds")
        return withUnsafeBufferPointer { $0[position] }
    }

    @inlinable public func withContiguousStorageIfAvailable<Result>(
        _ body: (UnsafeBufferPointer<UInt8>) throws -> Result
    ) rethrows -> Result? {
        try withUnsafeBufferPointer(body)
    }
}
