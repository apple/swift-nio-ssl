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
import NIOSSL

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
        XCTAssertEqual(Set([
            NIOSSLObjectIdentifier("1.1"),
        ]), Set([
            NIOSSLObjectIdentifier("1.1"),
        ]))
        XCTAssertEqual(Set([
            NIOSSLObjectIdentifier("1.1"),
            NIOSSLObjectIdentifier("1.2"),
        ]), Set([
            NIOSSLObjectIdentifier("1.2"),
            NIOSSLObjectIdentifier("1.1"),
        ]))
    }
    
    func testCustomStringConvertible() {
        XCTAssertEqual(NIOSSLObjectIdentifier("1.1")?.description, "1.1")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2")?.description, "1.2")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2.3")?.description, "1.2.3")
        XCTAssertEqual(NIOSSLObjectIdentifier("1.2.3.4")?.description, "1.2.3.4")
    }
}
