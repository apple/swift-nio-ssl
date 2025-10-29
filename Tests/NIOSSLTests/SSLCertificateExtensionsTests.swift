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

import XCTest

@testable import NIOSSL

final class SSLCertificateExtensionsTests: XCTestCase {
    func test() throws {
        let cert = try NIOSSLCertificate(bytes: Array(samplePemCert.utf8), format: .pem)

        XCTAssertEqual(cert._extensions.count, 3)
        let basicConstraint = try XCTUnwrap(
            cert._extensions.first(where: { $0.objectIdentifier == .init("2.5.29.19")! })
        )
        let subjectKeyIdentifier = try XCTUnwrap(
            cert._extensions.first(where: { $0.objectIdentifier == .init("2.5.29.14")! })
        )
        let authorityKeyIdentifier = try XCTUnwrap(
            cert._extensions.first(where: { $0.objectIdentifier == .init("2.5.29.35")! })
        )

        XCTAssertEqual(basicConstraint.isCritical, false)
        XCTAssertEqual(
            Array(basicConstraint.data),
            [
                0x30, 0x3, 0x1, 0x1, 0xFF,
            ]
        )

        XCTAssertEqual(subjectKeyIdentifier.isCritical, false)
        XCTAssertEqual(
            Array(subjectKeyIdentifier.data),
            [
                0x04, 0x14,
                0xE8, 0x3D, 0x19, 0x93, 0x05, 0x01, 0x05, 0xE4, 0x5E, 0x4B,
                0x70, 0xF8, 0x94, 0x23, 0x9A, 0x81, 0x34, 0xF0, 0x54, 0xF8,
            ]
        )

        XCTAssertEqual(authorityKeyIdentifier.isCritical, false)
        XCTAssertEqual(
            Array(authorityKeyIdentifier.data),
            [
                0x30, 0x16, 0x80, 0x14,
                0xE8, 0x3D, 0x19, 0x93, 0x05, 0x01, 0x05, 0xE4, 0x5E, 0x4B,
                0x70, 0xF8, 0x94, 0x23, 0x9A, 0x81, 0x34, 0xF0, 0x54, 0xF8,
            ]
        )
    }

    func testEmptyExtensions() {
        let extensions = NIOSSLCertificate._Extensions(takeOwnershipOf: nil)
        XCTAssertEqual(extensions.count, 0)
    }

    func testUnowned() throws {
        var owner: Optional = try NIOSSLCertificate(bytes: Array(samplePemCert.utf8), format: .pem)

        #if compiler(>=6.3)
        weak let weakReferenceToOwner = owner
        #else
        weak var weakReferenceToOwner = owner
        #endif

        var extensions: Optional = owner!._extensions
        XCTAssertEqual(extensions.map { Array($0) }?.count, 3)

        owner = nil
        XCTAssertNotNil(weakReferenceToOwner, "extensions should still have a strong reference to the owner")

        XCTAssertEqual(extensions.map { Array($0) }?.count, 3)

        extensions = nil
        XCTAssertNil(
            weakReferenceToOwner,
            "extensions are released and therefore no one should still have a strong reference to the owner"
        )
    }
}
