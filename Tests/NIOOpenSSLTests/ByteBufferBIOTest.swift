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

import XCTest
import NIO
import CNIOOpenSSL
@testable import NIOOpenSSL


final class ByteBufferBIOTest: XCTestCase {
    override func setUp() {
        guard openSSLIsInitialized else {
            fatalError("Cannot run tests without OpenSSL")
        }
    }

    private func retainedBIO() -> OpaquePointer {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        return swiftBIO.retainedBIO()
    }

    func testExtractingBIOWrite() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        XCTAssertNil(swiftBIO.outboundCiphertext())

        var bytesToWrite: [UInt8] = [1, 2, 3, 4, 5]
        let rc = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
        XCTAssertEqual(rc, 5)

        guard let extractedBytes = swiftBIO.outboundCiphertext().flatMap({ $0.getBytes(at: $0.readerIndex, length: $0.readableBytes) }) else {
            XCTFail("No received bytes")
            return
        }
        XCTAssertEqual(extractedBytes, bytesToWrite)
        XCTAssertNil(swiftBIO.outboundCiphertext())
    }

    func testManyBIOWritesAreCoalesced() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        XCTAssertNil(swiftBIO.outboundCiphertext())

        var bytesToWrite: [UInt8] = [1, 2, 3, 4, 5]
        var expectedBytes = [UInt8]()
        for _ in 0..<10 {
            let rc = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
            XCTAssertEqual(rc, 5)
            expectedBytes.append(contentsOf: bytesToWrite)
        }

        guard let extractedBytes = swiftBIO.outboundCiphertext().flatMap({ $0.getBytes(at: $0.readerIndex, length: $0.readableBytes) }) else {
            XCTFail("No received bytes")
            return
        }
        XCTAssertEqual(extractedBytes, expectedBytes)
        XCTAssertNil(swiftBIO.outboundCiphertext())
    }

    func testReadWithNoDataInBIO() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var targetBuffer = [UInt8](repeating: 0, count: 512)
        let rc = BIO_read(.make(optional: cBIO), &targetBuffer, 512)
        XCTAssertEqual(rc, -1)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) != 0)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_read(.make(optional: cBIO)) != 0)
        XCTAssertEqual(targetBuffer, [UInt8](repeating: 0, count: 512))
    }

    func testReadWithDataInBIO() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var inboundBytes = ByteBufferAllocator().buffer(capacity: 1024)
        inboundBytes.write(bytes: [1, 2, 3, 4, 5])
        swiftBIO.receiveFromNetwork(buffer: inboundBytes)

        var receivedBytes = ByteBufferAllocator().buffer(capacity: 1024)
        let rc = receivedBytes.writeWithUnsafeMutableBytes { pointer in
            let innerRC = BIO_read(.make(optional: cBIO), pointer.baseAddress!, CInt(pointer.count))
            XCTAssertTrue(innerRC > 0)
            return innerRC > 0 ? Int(innerRC) : 0
        }

        XCTAssertEqual(rc, 5)
        XCTAssertEqual(receivedBytes, inboundBytes)

        let secondRC = receivedBytes.withUnsafeMutableWritableBytes { pointer in
            BIO_read(.make(optional: cBIO), pointer.baseAddress!, CInt(pointer.count))
        }
        XCTAssertEqual(secondRC, -1)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) != 0)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_read(.make(optional: cBIO)) != 0)
    }

    func testShortReads() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var inboundBytes = ByteBufferAllocator().buffer(capacity: 1024)
        inboundBytes.write(bytes: [1, 2, 3, 4, 5])
        swiftBIO.receiveFromNetwork(buffer: inboundBytes)

        var receivedBytes = ByteBufferAllocator().buffer(capacity: 1024)
        for _ in 0..<5 {
            let rc = receivedBytes.writeWithUnsafeMutableBytes { pointer in
                let innerRC = BIO_read(.make(optional: cBIO), pointer.baseAddress!, 1)
                XCTAssertTrue(innerRC > 0)
                return innerRC > 0 ? Int(innerRC) : 0
            }

            XCTAssertEqual(rc, 1)
        }
        XCTAssertEqual(receivedBytes, inboundBytes)

        let secondRC = receivedBytes.withUnsafeMutableWritableBytes { pointer in
            BIO_read(.make(optional: cBIO), pointer.baseAddress!, CInt(pointer.count))
        }
        XCTAssertEqual(secondRC, -1)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) != 0)
        XCTAssertTrue(CNIOOpenSSL_BIO_should_read(.make(optional: cBIO)) != 0)
    }

    func testDropRefToBaseObjectOnRead() throws {
        let cBIO = self.retainedBIO()
        let receivedBytes = ByteBufferAllocator().buffer(capacity: 1024)
        receivedBytes.withVeryUnsafeBytes { pointer in
            let rc = BIO_read(.make(optional: cBIO), UnsafeMutableRawPointer(mutating: pointer.baseAddress!), 1)
            XCTAssertEqual(rc, -1)
            XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) == 0)
        }
    }

    func testDropRefToBaseObjectOnWrite() throws {
        let cBIO = self.retainedBIO()
        var receivedBytes = ByteBufferAllocator().buffer(capacity: 1024)
        receivedBytes.write(bytes: [1, 2, 3, 4, 5])
        receivedBytes.withVeryUnsafeBytes { pointer in
            let rc = BIO_write(.make(optional: cBIO), pointer.baseAddress!, 1)
            XCTAssertEqual(rc, -1)
            XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) == 0)
        }
    }

    func testZeroLengthReadsAlwaysSucceed() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var targetBuffer = [UInt8](repeating: 0, count: 512)
        let rc = BIO_read(.make(optional: cBIO), &targetBuffer, 0)
        XCTAssertEqual(rc, 0)
        XCTAssertEqual(targetBuffer, [UInt8](repeating: 0, count: 512))
    }

    func testWriteWhenHoldingBufferTriggersCoW() throws {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var bytesToWrite: [UInt8] = [1, 2, 3, 4, 5]
        let rc = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
        XCTAssertEqual(rc, 5)

        guard let firstWrite = swiftBIO.outboundCiphertext() else {
            XCTFail("Did not write")
            return
        }

        let secondRC = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
        XCTAssertEqual(secondRC, 5)
        guard let secondWrite = swiftBIO.outboundCiphertext() else {
            XCTFail("Did not write second time")
            return
        }

        XCTAssertNotEqual(firstWrite.baseAddress(), secondWrite.baseAddress())
    }

    func testWriteWhenDroppedBufferDoesNotTriggerCoW() {
        func writeAddress(swiftBIO: ByteBufferBIO, cBIO: OpaquePointer) -> UInt? {
            var bytesToWrite: [UInt8] = [1, 2, 3, 4, 5]
            let rc = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
            XCTAssertEqual(rc, 5)
            return swiftBIO.outboundCiphertext()?.baseAddress()
        }

        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        let firstAddress = writeAddress(swiftBIO: swiftBIO, cBIO: .init(cBIO))
        let secondAddress = writeAddress(swiftBIO: swiftBIO, cBIO: .init(cBIO))
        XCTAssertNotNil(firstAddress)
        XCTAssertNotNil(secondAddress)
        XCTAssertEqual(firstAddress, secondAddress)
    }

    func testZeroLengthWriteIsNoOp() {
        // This test works by emulating testWriteWhenHoldingBufferTriggersCoW, but
        // with the second write at zero length. This will not trigger a CoW, as no
        // actual write will occur.
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var bytesToWrite: [UInt8] = [1, 2, 3, 4, 5]
        let rc = BIO_write(.make(optional: cBIO), &bytesToWrite, 5)
        XCTAssertEqual(rc, 5)

        guard let firstWrite = swiftBIO.outboundCiphertext() else {
            XCTFail("Did not write")
            return
        }
        withExtendedLifetime(firstWrite) {
            let secondRC = BIO_write(.make(optional: cBIO), &bytesToWrite, 0)
            XCTAssertEqual(secondRC, 0)
            XCTAssertNil(swiftBIO.outboundCiphertext())
        }
    }

    func testSimplePuts() {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        XCTAssertNil(swiftBIO.outboundCiphertext())

        let stringToWrite = "Hello, world!"
        let rc = stringToWrite.withCString {
            BIO_puts(.make(optional: cBIO), $0)
        }
        XCTAssertEqual(rc, 13)

        let extractedString = swiftBIO.outboundCiphertext().flatMap { $0.getString(at: $0.readerIndex, length: $0.readableBytes) }
        XCTAssertEqual(extractedString, stringToWrite)
        XCTAssertNil(swiftBIO.outboundCiphertext())
    }

    func testGetsNotSupported() {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.write(staticString: "Hello, world!")
        swiftBIO.receiveFromNetwork(buffer: buffer)

        buffer.withUnsafeMutableReadableBytes { pointer in
            let myPointer = pointer.baseAddress!.bindMemory(to: Int8.self, capacity: pointer.count)
            let rc = BIO_gets(.make(optional: cBIO), myPointer, CInt(pointer.count))
            XCTAssertEqual(rc, -2)
            XCTAssertTrue(CNIOOpenSSL_BIO_should_retry(.make(optional: cBIO)) == 0)
        }
    }

    func testBasicCtrlDance() {
        let swiftBIO = ByteBufferBIO(allocator: ByteBufferAllocator())
        let cBIO = swiftBIO.retainedBIO()
        defer {
            BIO_free(.make(optional: cBIO))
        }

        let originalShutdown = CNIOOpenSSL_BIO_get_close(.make(optional: cBIO))
        XCTAssertEqual(originalShutdown, BIO_CLOSE)

        let rc = CNIOOpenSSL_BIO_set_close(.make(optional: cBIO), CLong(BIO_NOCLOSE))
        XCTAssertEqual(rc, 1)

        let newShutdown = CNIOOpenSSL_BIO_get_close(.make(optional: cBIO))
        XCTAssertEqual(newShutdown, BIO_NOCLOSE)

        let rc2 = CNIOOpenSSL_BIO_set_close(.make(optional: cBIO), CLong(BIO_CLOSE))
        XCTAssertEqual(rc2, 1)

        let newShutdown2 = CNIOOpenSSL_BIO_get_close(.make(optional: cBIO))
        XCTAssertEqual(newShutdown2, BIO_CLOSE)
    }
}


extension ByteBuffer {
    func baseAddress() -> UInt {
        return self.withVeryUnsafeBytes { return UInt(bitPattern: $0.baseAddress! )}
    }
}
