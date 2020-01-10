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

import Foundation
import XCTest
import NIO
@testable import NIOSSL

class SSLPrivateKeyTest: XCTestCase {
    static var pemKeyFilePath: String! = nil
    static var derKeyFilePath: String! = nil
    static var passwordPemKeyFilePath: String! = nil
    static var passwordPKCS8PemKeyFilePath: String! = nil
    static var dynamicallyGeneratedKey: NIOSSLPrivateKey! = nil

    override class func setUp() {
        SSLPrivateKeyTest.pemKeyFilePath = try! dumpToFile(text: samplePemKey,
                                                           fileExtension: ".pem")
        SSLPrivateKeyTest.derKeyFilePath = try! dumpToFile(data: sampleDerKey)
        SSLPrivateKeyTest.passwordPemKeyFilePath = try! dumpToFile(text: samplePemRSAEncryptedKey,
                                                                   fileExtension: ".pem")
        SSLPrivateKeyTest.passwordPKCS8PemKeyFilePath = try! dumpToFile(text: samplePKCS8PemPrivateKey)

        let (_, key) = generateSelfSignedCert()
        SSLPrivateKeyTest.dynamicallyGeneratedKey = key
    }

    override class func tearDown() {
        _ = SSLPrivateKeyTest.pemKeyFilePath.withCString {
            unlink($0)
        }
        _ = SSLPrivateKeyTest.derKeyFilePath.withCString {
            unlink($0)
        }
        _ = SSLPrivateKeyTest.passwordPemKeyFilePath.withCString {
            unlink($0)
        }
        _ = SSLPrivateKeyTest.passwordPKCS8PemKeyFilePath.withCString {
            unlink($0)
        }
    }

    func testLoadingPemKeyFromFile() throws {
        let key1 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.pemKeyFilePath, format: .pem)
        let key2 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.pemKeyFilePath, format: .pem)

        XCTAssertEqual(key1, key2)
        XCTAssertNotEqual(key1, SSLPrivateKeyTest.dynamicallyGeneratedKey)
    }

    func testLoadingDerKeyFromFile() throws {
        let key1 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.derKeyFilePath, format: .der)
        let key2 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.derKeyFilePath, format: .der)

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
        XCTAssertNotEqual(key1, SSLPrivateKeyTest.dynamicallyGeneratedKey)
        XCTAssertNotEqual(key1.hashValue, SSLPrivateKeyTest.dynamicallyGeneratedKey.hashValue)
    }

    func testDerAndPemAreIdentical() throws {
        let key1 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.pemKeyFilePath, format: .pem)
        let key2 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.derKeyFilePath, format: .der)

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
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

        do {
            _ = try NIOSSLPrivateKey(bytes: keyBytes, format: .pem)
            XCTFail("Gibberish successfully loaded")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        do {
            _ = try NIOSSLPrivateKey(bytes: keyBytes, format: .der)
            XCTFail("Gibberish successfully loaded")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromFileAsPemFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        do {
            _ = try NIOSSLPrivateKey(file: tempFile, format: .pem)
            XCTFail("Gibberish successfully loaded")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // Do nothing.
        }
    }

    func testLoadingGibberishFromFileAsDerFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        do {
            _ = try NIOSSLPrivateKey(file: tempFile, format: .der)
            XCTFail("Gibberish successfully loaded")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // Do nothing.
        }
    }

    func testLoadingNonexistentFileAsPem() throws {
        do {
            _ = try NIOSSLPrivateKey(file: "/nonexistent/path", format: .pem)
            XCTFail("Did not throw")
        } catch let error as IOError {
            XCTAssertEqual(error.errnoCode, ENOENT)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testLoadingNonexistentFileAsDer() throws {
        do {
            _ = try NIOSSLPrivateKey(file: "/nonexistent/path", format: .der)
            XCTFail("Did not throw")
        } catch let error as IOError {
            XCTAssertEqual(error.errnoCode, ENOENT)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testLoadingNonexistentFileAsPemWithPassphrase() throws {
        do {
            _ = try NIOSSLPrivateKey(file: "/nonexistent/path", format: .pem) { (_: NIOSSLPassphraseSetter<Array<UInt8>>) in
                XCTFail("Should not be called")
            }
            XCTFail("Did not throw")
        } catch let error as IOError {
            XCTAssertEqual(error.errnoCode, ENOENT)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testLoadingNonexistentFileAsDerWithPassphrase() throws {
        do {
            _ = try NIOSSLPrivateKey(file: "/nonexistent/path", format: .der) { (_: NIOSSLPassphraseSetter<Array<UInt8>>) in
                XCTFail("Should not be called")
            }
            XCTFail("Did not throw")
        } catch let error as IOError {
            XCTAssertEqual(error.errnoCode, ENOENT)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testLoadingEncryptedRSAKeyFromMemory() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in closure("thisisagreatpassword".utf8) }
        let key2 = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in closure("thisisagreatpassword".utf8) }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingEncryptedRSAPKCS8KeyFromMemory() throws {
        let key1 = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in closure("thisisagreatpassword".utf8) }
        let key2 = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in closure("thisisagreatpassword".utf8) }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingEncryptedRSAKeyFromFile() throws {
        let key1 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.passwordPemKeyFilePath, format: .pem) { closure in closure("thisisagreatpassword".utf8) }
        let key2 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.passwordPemKeyFilePath, format: .pem) { closure in closure("thisisagreatpassword".utf8) }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testLoadingEncryptedRSAPKCS8KeyFromFile() throws {
        let key1 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.passwordPKCS8PemKeyFilePath, format: .pem) { closure in closure("thisisagreatpassword".utf8) }
        let key2 = try NIOSSLPrivateKey(file: SSLPrivateKeyTest.passwordPKCS8PemKeyFilePath, format: .pem) { closure in closure("thisisagreatpassword".utf8) }

        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.hashValue, key2.hashValue)
    }

    func testWildlyOverlongPassphraseRSAFromMemory() throws {
        do {
            _ = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in closure(Array(repeating: UInt8(8), count: 1 << 16)) }
            XCTFail("Should not have created the key")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // ok
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testWildlyOverlongPassphrasePKCS8FromMemory() throws {
        do {
            _ = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in closure(Array(repeating: UInt8(8), count: 1 << 16)) }
            XCTFail("Should not have created the key")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // ok
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testWildlyOverlongPassphraseRSAFromFile() throws {
        do {
            _ = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { closure in closure(Array(repeating: UInt8(8), count: 1 << 16)) }
            XCTFail("Should not have created the key")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // ok
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testWildlyOverlongPassphrasePKCS8FromFile() throws {
        do {
            _ = try NIOSSLPrivateKey(bytes: .init(samplePKCS8PemPrivateKey.utf8), format: .pem) { closure in closure(Array(repeating: UInt8(8), count: 1 << 16)) }
            XCTFail("Should not have created the key")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // ok
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testThrowingPassphraseCallback() throws {
        enum MyError: Error {
            case error
        }

        do {
            _ = try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) { (_: NIOSSLPassphraseSetter<Array<UInt8>>) in
                throw MyError.error
            }
            XCTFail("Should not have created the key")
        } catch NIOSSLError.failedToLoadPrivateKey {
            // ok
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testWrongPassword() {
        XCTAssertThrowsError(try NIOSSLPrivateKey(bytes: .init(samplePemRSAEncryptedKey.utf8), format: .pem) {
            closure in closure("incorrect password".utf8)
        }) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
        }
    }

    func testMissingPassword() {
        let configuration = TLSConfiguration.forServer(certificateChain: [],
                                                       privateKey: .file(SSLPrivateKeyTest.passwordPemKeyFilePath))

        XCTAssertThrowsError(try NIOSSLContext(configuration: configuration)) { error in
            XCTAssertEqual(.failedToLoadPrivateKey, error as? NIOSSLError)
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
}
