//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import XCTest

@testable import NIOSSL

class SSLPrivateKeyTest: XCTestCase {
    static let dynamicallyGeneratedKey = generateSelfSignedCert().1

    static func withPEMKeyFile(_ body: (String) throws -> Void) throws {
        let path = try dumpToFile(
            text: samplePemKey,
            fileExtension: ".pem"
        )
        defer {
            unlink(path)
        }

        return try body(path)
    }

    static func withDERKeyFile(_ body: (String) throws -> Void) throws {
        let path = try dumpToFile(
            data: sampleDerKey
        )
        defer {
            unlink(path)
        }

        return try body(path)
    }

    static func withPasswordPEMKeyFile(_ body: (String) throws -> Void) throws {
        let path = try dumpToFile(
            text: samplePemRSAEncryptedKey,
            fileExtension: ".pem"
        )
        defer {
            unlink(path)
        }

        return try body(path)
    }

    static func withPasswordPKCS8PEMKeyFile(_ body: (String) throws -> Void) throws {
        let path = try dumpToFile(
            text: samplePKCS8PemPrivateKey
        )
        defer {
            unlink(path)
        }

        return try body(path)
    }

    func testLoadingPemKeyFromFile() throws {
        try Self.withPEMKeyFile { pemKeyFilePath in
            let key1 = try NIOSSLPrivateKey(file: pemKeyFilePath, format: .pem)
            let key2 = try NIOSSLPrivateKey(file: pemKeyFilePath, format: .pem)

            XCTAssertEqual(key1, key2)
            XCTAssertNotEqual(key1, SSLPrivateKeyTest.dynamicallyGeneratedKey)
        }
    }

    func testLoadingDerKeyFromFile() throws {
        try Self.withDERKeyFile { derKeyFilePath in
            let key1 = try NIOSSLPrivateKey(file: derKeyFilePath, format: .der)
            let key2 = try NIOSSLPrivateKey(file: derKeyFilePath, format: .der)

            XCTAssertEqual(key1, key2)
            XCTAssertEqual(key1.hashValue, key2.hashValue)
            XCTAssertNotEqual(key1, SSLPrivateKeyTest.dynamicallyGeneratedKey)
            XCTAssertNotEqual(key1.hashValue, SSLPrivateKeyTest.dynamicallyGeneratedKey.hashValue)
        }
    }

    func testDerAndPemAreIdentical() throws {
        try Self.withPEMKeyFile { pemKeyFilePath in
            try Self.withDERKeyFile { derKeyFilePath in
                let key1 = try NIOSSLPrivateKey(file: pemKeyFilePath, format: .pem)
                let key2 = try NIOSSLPrivateKey(file: derKeyFilePath, format: .der)

                XCTAssertEqual(key1, key2)
                XCTAssertEqual(key1.hashValue, key2.hashValue)
            }
        }
    }

    func testLoadingPemKeyFromMemory() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePemKey.utf8), format: .pem)
        let key2 = try NIOSSLPrivateKey(bytes: .init(samplePemKey.utf8), format: .pem)

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingDerKeyFromMemory() throws {
        let keyBytes = [UInt8](sampleDerKey)
        let key1 = try NIOSSLPrivateKey(bytes: keyBytes, format: .der)
        let key2 = try NIOSSLPrivateKey(bytes: keyBytes, format: .der)

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingGibberishFromMemoryAsPemFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        XCTAssertThrowsError(try NIOSSLPrivateKey(bytes: keyBytes, format: .pem)) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        XCTAssertThrowsError(try NIOSSLPrivateKey(bytes: keyBytes, format: .der)) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsPemFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLPrivateKey(file: tempFile, format: .pem)) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsDerFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLPrivateKey(file: tempFile, format: .der)) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testLoadingNonexistentFileAsPem() throws {

        XCTAssertThrowsError(try NIOSSLPrivateKey(file: "/nonexistent/path", format: .pem)) { error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testLoadingNonexistentFileAsDer() throws {
        XCTAssertThrowsError(try NIOSSLPrivateKey(file: "/nonexistent/path", format: .der)) { error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testLoadingNonexistentFileAsPemWithPassphrase() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(file: "/nonexistent/path", format: .pem) { (_: NIOSSLPassphraseSetter<[UInt8]>) in
                XCTFail("Should not be called")
            }
        ) { error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testLoadingNonexistentFileAsDerWithPassphrase() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(file: "/nonexistent/path", format: .der) { (_: NIOSSLPassphraseSetter<[UInt8]>) in
                XCTFail("Should not be called")
            }
        ) { error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testLoadingEncryptedRSAKeyFromMemory() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in
            closure("thisisagreatpassword".utf8)
        }
        let key2 = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in
            closure("thisisagreatpassword".utf8)
        }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingEncryptedRSAPKCS8KeyFromMemory() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in
            closure("thisisagreatpassword".utf8)
        }
        let key2 = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in
            closure("thisisagreatpassword".utf8)
        }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingEncryptedRSAKeyFromFile() throws {
        try Self.withPasswordPEMKeyFile { passwordPemKeyFilePath in
            let key1 = try NIOSSLPrivateKey(file: passwordPemKeyFilePath, format: .pem) { closure in
                closure("thisisagreatpassword".utf8)
            }
            let key2 = try NIOSSLPrivateKey(file: passwordPemKeyFilePath, format: .pem) { closure in
                closure("thisisagreatpassword".utf8)
            }

            XCTAssertEqual(key1, key2)
            XCTAssertEqual(key1.hashValue, key2.hashValue)
        }
    }

    func testLoadingEncryptedRSAPKCS8KeyFromFile() throws {
        try Self.withPasswordPKCS8PEMKeyFile { passwordPKCS8PemKeyFilePath in
            let key1 = try NIOSSLPrivateKey(file: passwordPKCS8PemKeyFilePath, format: .pem) { closure in
                closure("thisisagreatpassword".utf8)
            }
            let key2 = try NIOSSLPrivateKey(file: passwordPKCS8PemKeyFilePath, format: .pem) { closure in
                closure("thisisagreatpassword".utf8)
            }

            XCTAssertEqual(key1, key2)
            XCTAssertEqual(key1.hashValue, key2.hashValue)
        }
    }

    func testWildlyOverlongPassphraseRSAFromMemory() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in
                closure(Array(repeating: UInt8(8), count: 1 << 16))
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testWildlyOverlongPassphrasePKCS8FromMemory() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in
                closure(Array(repeating: UInt8(8), count: 1 << 16))
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testWildlyOverlongPassphraseRSAFromFile() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in
                closure(Array(repeating: UInt8(8), count: 1 << 16))
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testWildlyOverlongPassphrasePKCS8FromFile() throws {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in
                closure(Array(repeating: UInt8(8), count: 1 << 16))
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testThrowingPassphraseCallback() throws {
        enum MyError: Error {
            case error
        }

        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) {
                (_: NIOSSLPassphraseSetter<[UInt8]>) in
                throw MyError.error
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testWrongPassword() {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) {
                closure in closure("incorrect password".utf8)
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    @available(*, deprecated, message: "`.file` NIOSSLPrivateKeySource option deprecated")
    func testMissingPassword() throws {
        try Self.withPasswordPEMKeyFile { passwordPemKeyFilePath in
            let configuration = TLSConfiguration.makeServerConfiguration(
                certificateChain: [],
                privateKey: .file(passwordPemKeyFilePath)
            )

            XCTAssertThrowsError(try NIOSSLContext(configuration: configuration)) { error in
                XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
            }
        }
    }

    func testECKeysWorkProperly() throws {
        let keyDerBytes = [UInt8](sampleECDerKey)
        let keyPemBytes = [UInt8](sampleECPemKey.utf8)

        let key1 = try assertNoThrowWithValue(NIOSSLPrivateKey(bytes: keyDerBytes, format: .der))
        let key2 = try assertNoThrowWithValue(NIOSSLPrivateKey(bytes: keyPemBytes, format: .pem))

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testECKeysArentEqualToRSAKeys() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePemKey.utf8), format: .pem)
        let key2 = try NIOSSLPrivateKey(bytes: .init(sampleECPemKey.utf8), format: .pem)

        XCTAssertNotEqual(key1, key2)
        XCTAssertNotEqual(key1.hashValue, key2.hashValue)
    }

    func testDERBytes() throws {
        let key = try NIOSSLPrivateKey(bytes: .init(samplePemKey.utf8), format: .pem)
        let derBytes = try key.derBytes
        XCTAssertEqual(Data(derBytes), pemToDer(samplePemKey))
    }

    func testLoadingNonASCIIPassphraseEncryptedKeyFromMemory() throws {
        let expected = try NIOSSLPrivateKey(bytes: .init(sampleECPemNonASCIIPassphraseKey.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(bytes: .init(sampleECPKCS8PemNonASCIIPassphraseKey.utf8), format: .pem) {
            closure in closure("He\u{DF}".utf8)
        }

        XCTAssertEqual(key, expected)
        XCTAssertEqual(key.hashValue, expected.hashValue)
    }

    func testLoadingNonASCIIPassphraseEncryptedKeyFromFile() throws {
        let path = try dumpToFile(text: sampleECPKCS8PemNonASCIIPassphraseKey, fileExtension: ".pem")
        defer {
            unlink(path)
        }

        let expected = try NIOSSLPrivateKey(bytes: .init(sampleECPemNonASCIIPassphraseKey.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(file: path, format: .pem) { closure in
            closure([0x48, 0x65, 0xC3, 0x9F])
        }

        XCTAssertEqual(key, expected)
        XCTAssertEqual(key.hashValue, expected.hashValue)
    }

    func testWrongNonASCIIPassphraseFails() {
        XCTAssertThrowsError(
            try NIOSSLPrivateKey(bytes: .init(sampleECPKCS8PemNonASCIIPassphraseKey.utf8), format: .pem) {
                closure in closure("He\u{DF}\u{DF}".utf8)
            }
        ) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testPassphraseCallbackPreservesAllByteValues() {
        let passphrase = Array(UInt8(1)...UInt8(255))
        let manager = BoringSSLPassphraseCallbackManager { setter in setter(passphrase) }
        let buffer = UnsafeMutableBufferPointer<CChar>.allocate(capacity: 256)
        defer {
            buffer.deallocate()
        }
        buffer.initialize(repeating: CChar(truncatingIfNeeded: 0x55))

        let count = manager.invoke(buffer: buffer)

        XCTAssertEqual(count, 255)
        XCTAssertEqual(buffer[0..<255].map { UInt8(truncatingIfNeeded: $0) }, passphrase)
        XCTAssertEqual(buffer[255], 0)
    }

    func testPassphraseCallbackNonASCIIPassphraseAtBufferLimit() {
        let buffer = UnsafeMutableBufferPointer<CChar>.allocate(capacity: 8)
        defer {
            buffer.deallocate()
        }

        // Exactly buffer.count - 1 bytes: all bytes are copied and the last slot gets a NUL.
        let fits: [UInt8] = [0x48, 0x65, 0xC3, 0x9F, 0xE2, 0x82, 0xAC]
        buffer.initialize(repeating: CChar(truncatingIfNeeded: 0x55))
        let fitsManager = BoringSSLPassphraseCallbackManager { setter in setter(fits) }
        XCTAssertEqual(fitsManager.invoke(buffer: buffer), CInt(fits.count))
        XCTAssertEqual(buffer[0..<fits.count].map { UInt8(truncatingIfNeeded: $0) }, fits)
        XCTAssertEqual(buffer[fits.count], 0)

        // Exactly buffer.count bytes: there is no room for the NUL, so nothing is copied.
        let tooLong: [UInt8] = fits + [0xFF]
        buffer.initialize(repeating: CChar(truncatingIfNeeded: 0x55))
        let tooLongManager = BoringSSLPassphraseCallbackManager { setter in setter(tooLong) }
        XCTAssertEqual(tooLongManager.invoke(buffer: buffer), 0)
        XCTAssertEqual(UInt8(truncatingIfNeeded: buffer[0]), 0x55)
    }

    func testRoundTripNonASCIIPassphrase() throws {
        let passphrase = "He\u{DF}\u{20AC}\u{1F600}"
        let original = SSLPrivateKeyTest.dynamicallyGeneratedKey
        let path = try NIOSSLIntegrationTest.keyInFile(key: original, passphrase: passphrase)
        defer {
            unlink(path)
        }

        let key = try NIOSSLPrivateKey(file: path, format: .pem) { closure in
            closure(passphrase.utf8)
        }

        XCTAssertEqual(key, original)
    }

    func testRoundTripSingleHighBytePassphrase() throws {
        let original = SSLPrivateKeyTest.dynamicallyGeneratedKey

        for byte: UInt8 in [0x80, 0xFF] {
            let passphrase = [byte]
            let pem = encryptedPEM(key: original, passphrase: passphrase)

            let key = try NIOSSLPrivateKey(bytes: pem, format: .pem) { closure in
                closure(passphrase)
            }

            XCTAssertEqual(key, original, "passphrase byte \(byte)")
        }
    }
}
