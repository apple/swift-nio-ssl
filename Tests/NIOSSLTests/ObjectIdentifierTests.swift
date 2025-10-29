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
import XCTest

@testable import NIOSSL

private final class OIDMemoryOwner {
    var reference: OpaquePointer!
    public init?(_ string: String) {
        let result = string.withCString { string in
            CNIOBoringSSL_OBJ_txt2obj(string, 1)
        }
        guard let reference = result else {
            return nil
        }
        self.reference = reference
    }
    deinit {
        CNIOBoringSSL_ASN1_OBJECT_free(self.reference)
    }
}

final class ObjectIdentifierTests: XCTestCase {
    func testEquatable() {
        XCTAssertEqual(
            NIOSSLObjectIdentifier("1.1"),
            NIOSSLObjectIdentifier("1.1")
        )
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2"), NIOSSLObjectIdentifier("1.2"))
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2.3"), NIOSSLObjectIdentifier("1.2.3"))

        XCTAssertNotEqual(NIOSSLObjectIdentifier("1"), NIOSSLObjectIdentifier("1.2"))
        XCTAssertNotEqual(NIOSSLObjectIdentifier("1.2"), NIOSSLObjectIdentifier("1.2.3"))
    }

    func testHashable() {
        XCTAssertEqual(
            Set([
                NIOSSLObjectIdentifier("1.1")
            ]),
            Set([
                NIOSSLObjectIdentifier("1.1")
            ])
        )
        XCTAssertEqual(
            Set([
                NIOSSLObjectIdentifier("1.1"),
                NIOSSLObjectIdentifier("1.2"),
            ]),
            Set([
                NIOSSLObjectIdentifier("1.2"),
                NIOSSLObjectIdentifier("1.1"),
            ])
        )
    }

    func testCustomStringConvertible() {
        XCTAssertEqual(NIOSSLObjectIdentifier("1.1")?.description, "1.1")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2")?.description, "1.2")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2.3")?.description, "1.2.3")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2.3.4")?.description, "1.2.3.4")
    }

    func testUnowned() {
        var owner: Optional = OIDMemoryOwner("1.2.3")!

        #if compiler(>=6.3)
        weak let weakReferenceToOwner = owner
        #else
        weak var weakReferenceToOwner = owner
        #endif

        var oid: Optional = NIOSSLObjectIdentifier(borrowing: owner!.reference, owner: owner!)
        XCTAssertEqual(oid?.description, "1.2.3")

        owner = nil
        XCTAssertNotNil(weakReferenceToOwner, "OID should still have a strong reference to the owner")

        XCTAssertEqual(oid?.description, "1.2.3")

        oid = nil
        XCTAssertNil(
            weakReferenceToOwner,
            "OID is released and therefore no one should still have a strong reference to the owner"
        )
    }

    func testCopy() {
        var owner: Optional = OIDMemoryOwner("1.2.3")!

        #if compiler(>=6.3)
        weak let weakReferenceToOwner = owner
        #else
        weak var weakReferenceToOwner = owner
        #endif

        let oid: Optional = withExtendedLifetime(owner) {
            NIOSSLObjectIdentifier(copyOf: $0?.reference)
        }

        XCTAssertEqual(oid?.description, "1.2.3")
        owner = nil
        XCTAssertNil(weakReferenceToOwner, "OID should no longer have a strong reference to the owner")

        XCTAssertEqual(oid?.description, "1.2.3", "copy should still work after the original owner is deallocated")
    }
}
