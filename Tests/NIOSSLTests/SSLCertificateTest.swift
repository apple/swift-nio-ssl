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

let multiSanCert = """
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIURiMaUmhI1Xr0mZ4p+JmI0XjZTaIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE3MTAzMDEyMDUwMFoXDTQwMDEw
MTAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA26DcKAxqdWivhS/J3Klf+cEnrT2cDzLhmVRCHuQZXiIr
tqr5401KDbRTVOg8v2qIyd8x4+YbpE47JP3fBrcMey70UK/Er8nu28RY3z7gZLLi
Yf+obHdDFCK5JaCGmM61I0c0vp7aMXsyv7h3vjEzTuBMlKR8p37ftaXSUAe3Qk/D
/fzA3k02E2e3ap0Sapd/wUu/0n/MFyy9HkkeykivAzLaaFhhvp3hATdFYC4FLld8
OMB60bC2S13CAljpMlpjU/XLLOUbaPgnNUqE1nFqFBoTl6kV6+ii8Dd5ENVvE7pE
SoNoyGLDUkDRJJMNUHAo0zbxyhd7WOtyZ7B4YBbPswIDAQABo10wWzBLBgNVHREE
RDBCgglsb2NhbGhvc3SCC2V4YW1wbGUuY29tgRB1c2VyQGV4YW1wbGUuY29thwTA
qAABhxAgAQ24AAAAAAAAAAAAAAABMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
BQADggEBACYBArIoL9ZzVX3M+WmTD5epmGEffrH7diRJZsfpVXi86brBPrbvpTBx
Fa+ZKxBAchPnWn4rxoWVJmTm4WYqZljek7oQKzidu88rMTbsxHA+/qyVPVlQ898I
hgnW4h3FFapKOFqq5Hj2gKKItFIcGoVY2oLTBFkyfAx0ofromGQp3fh58KlPhC0W
GX1nFCea74mGyq60X86aEWiyecYYj5AEcaDrTnGg3HLGTsD3mh8SUZPAda13rO4+
RGtGsA1C9Yovlu9a6pWLgephYJ73XYPmRIGgM64fkUbSuvXNJMYbWnzpoCdW6hka
IEaDUul/WnIkn/JZx8n+wgoWtyQa4EA=
-----END CERTIFICATE-----
"""

let multiCNCert = """
-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIUR6eOMdEFZAqorykK6u6rwPGfsh0wDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxEjAQBgNVBAMMCUlnbm9yZSBtZTERMA8GA1UECAwI
TmVicmFza2ExEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNzExMDIxMzM5MjRaFw00
MDAxMDEwMDAwMDBaMEgxCzAJBgNVBAYTAlVTMRIwEAYDVQQDDAlJZ25vcmUgbWUx
ETAPBgNVBAgMCE5lYnJhc2thMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCb/wE6/pF40KmF4bgtrlInWIojsDma08q7
cK9LpzifjYNTrlTv7+8tR3TRkWwThW4sMGckq9u1Bty9aF50sazBZaLDZYoamuHS
43T7hj4aX++lEq+inlXaNX3WmKkq0y0ANLBsXaLC+8J+xemlXErBsacK1Lz8Yz//
lVOwD85LG6UN87j8L/L5+t922HyGhQRVTvcbmXa05JovMXILXnoUeEvNteZZtLa0
zcpO+9pN/VwmxVOnQncxTG81FV6Qypx7YFf16QyEDVkXrt7/l6k+I+sAzBHIn28Y
cPq/HfcAbWPU+gMiCLCplDi5NCyL7yyiG7bEjxR0oiWhzZG1abgjAgMBAAGjEDAO
MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAFAknMMePElmNsuzEUWO
m2a6n/cHEaJzDEVLbFifcCUNU2U6o2bgXrJIBjFudISYPjpG+gmnuAwdfu6CA63M
wiuLaLQASz6W12pRqlIriUazDn4JnIHu8wCHj8QkYTV7HunhtGJjX7xT89dRS5Y/
IJv0Q9J2CZ16d3ETCzWp2Djq1IPggkBrsgKalJmwsiWi8UkH/GeMA+YQ1p8r9Bvp
+Jd1VitqxJFG5tgT68dq1LxlsNb4L1Cm15m8LdhY5BgSO2AG9G4gBbO0ixZJwHbn
TLiPC0Jd3x5tf9qeSv1eWHuhQd9R908EhZdC6rgN8fZfMux2tQxNbIsNPYAQhmsB
/nc=
-----END CERTIFICATE-----
"""

let noCNCert = """
-----BEGIN CERTIFICATE-----
MIIC3jCCAcagAwIBAgIUeB9gFXDDe/kTcsPGlHIZ4M+SpyYwDQYJKoZIhvcNAQEL
BQAwIDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5lYnJhc2thMB4XDTE3MTEwMjEz
NDIwMFoXDTQwMDEwMTAwMDAwMFowIDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
YnJhc2thMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2DqRr+tIXVXz
4VZA5dSJo4pPgC+lNngg8Bpk9pedmOj8GSdvbIkRmXPRqOIw33vurfGVqcYiX3DH
HcVKS6ZF/ylE4dDH7JmGvCYpJTK6+02nkpdz3CzoX8lIRHBSJAJwny/UK20QBhsU
OWm/mD0uCRfgfp9FasKqA56OBFGNYAOTAM33RHuXQNSSfV5FmSmNkWsiM1S+EUgH
PptKQlXUfiSUFBCuyy9iItSg2fOew3C6/dXJ47T4mFi5qD/WKmI3uSNqBKNPcHI8
EGZX4r8w0Hvq2hV13t+hexaLkS6VeZWb1kTrdgDPnjcl43txePPP7tEGRlZFO+bI
V2j0pGb/iwIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IB
AQC27ElJn7TWhr2WcPsdXxGNUpepFgXEsEAVnoiJPI9XqXdOZCFWTUmRXrQICPUn
8HnVfYTFl/WZnTYhf8Ky5RB1W3X0Juo7MGge7mx6D6m8yJVBecQxPasVienTvdDg
UZI2oodxnS7egFwlvFM2ZUmPLVvq0B7VQBSa2Ix3FChNtJ1u5yfHyoDUMRfYl0bF
0B3poAgLDW3FUQ7QoErMvslUJrFxmJXUKKdhg9z6jQTdcmZ6Dr8sFZQkRADbJRzm
AYqSreeyevxdoNwQrpZMAGm61nc7OS8i0Q0JRe3FpGD29BMS0ystlzDeNnUpf+yJ
u9dFQrCkq8MilGSO1L2bZsqY
-----END CERTIFICATE-----
"""

let unicodeCNCert = """
-----BEGIN CERTIFICATE-----
MIICyjCCAbKgAwIBAgIUeK7KUVK7tcUhxVnkSWEsqHj07TEwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLc3RyYcOfZS5vcmcwHhcNMTcxMTAyMTM0NzQxWhcNNDAw
MTAxMDAwMDAwWjAWMRQwEgYDVQQDDAtzdHJhw59lLm9yZzCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAO0Anpw+WpM897YXUNHI4oTr4BUxIcOC2A7LQiQ0
briNXLIaIN8irwaa4TwCqvjg2B09GGO7EWvi0EX050X0jFFiSDdGhSZGMLL34nfk
/HW14XjTCW+LkYcFAyOD8Kf3nGGLagIdtnPWQ3Atf6rTf5A35K75+penURN226xB
t0vKqtngYTFu0n6B/+Ip6FI/Bq8yyGtPN74yR79KG3WL7mvrEHxv+TnZkb2F6f2j
cJALEJPx8wFug154EnRDOURZMX5gmHRR/Xm9jP1R7Rch+4Ue2Fy38C1a35p0Saap
JDKSmxr2430bQ5S41BTT5Q3N6eBD7f+cqaQyoa0u+qvl+gcCAwEAAaMQMA4wDAYD
VR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAM7x+J+A2UN+RCKEjJUc9rM3S
G9AxfhKO3VN1mrPRs6JG1ED7t/9e2xdjLRRl84Rz9jnaKVTS2sQ8yKYejWGUbXDq
WO6KNlrjzspL3M8EIoi7QNwtRktviCkkxxwhzDfuH9N6ncjq0qod0vxGq0nqxrAo
VJto6NnrshZEQHGF8uipOFPNTDAR0SpzyzXaK59oqSPJ5VrZiQ3p8izVuRE9r1u2
i5PCcPYi39q101UIxV/WokS0mqHx/XuTYTwhWYd/C49OnM8MLZOUJd8w0VvS0ItY
/wAv4vk0ScS4KmXTJBBGSiBqLdroaM9VKcA1p7TN0vzlut2E/nKmBhgzQJFKZA==
-----END CERTIFICATE-----
"""

func makeTemporaryFile(fileExtension: String = "") -> String {
    let template = "/tmp/niotestXXXXXXX\(fileExtension)"
    var templateBytes = template.utf8 + [0]
    let fd = templateBytes.withUnsafeMutableBufferPointer { ptr in
        ptr.baseAddress!.withMemoryRebound(to: Int8.self, capacity: ptr.count) { (ptr: UnsafeMutablePointer<Int8>) in
            return mkstemps(ptr, CInt(fileExtension.utf8.count))
        }
    }
    close(fd)
    templateBytes.removeLast()
    return String(decoding: templateBytes, as: UTF8.self)
}

internal func dumpToFile(data: Data, fileExtension: String = "") throws  -> String {
    let filename = makeTemporaryFile(fileExtension: fileExtension)
    try data.write(to: URL(fileURLWithPath: filename))
    return filename
}

internal func dumpToFile(text: String, fileExtension: String = "") throws -> String {
    return try dumpToFile(data: text.data(using: .utf8)!, fileExtension: fileExtension)
}

class SSLCertificateTest: XCTestCase {
    static var pemCertFilePath: String! = nil
    static var pemCertsFilePath: String! = nil
    static var derCertFilePath: String! = nil
    static var dynamicallyGeneratedCert: NIOSSLCertificate! = nil

    override class func setUp() {
        SSLCertificateTest.pemCertFilePath = try! dumpToFile(text: samplePemCert)
        SSLCertificateTest.pemCertsFilePath = try! dumpToFile(text: samplePemCerts)
        SSLCertificateTest.derCertFilePath = try! dumpToFile(data: sampleDerCert)

        let (cert, _) = generateSelfSignedCert()
        SSLCertificateTest.dynamicallyGeneratedCert = cert
    }

    override class func tearDown() {
        _ = SSLCertificateTest.pemCertFilePath.withCString {
            unlink($0)
        }
        _ = SSLCertificateTest.pemCertsFilePath.withCString {
            unlink($0)
        }
        _ = SSLCertificateTest.derCertFilePath.withCString {
            unlink($0)
        }
    }

    func testLoadingPemCertFromFile() throws {
        let cert1 = try NIOSSLCertificate(file: SSLCertificateTest.pemCertFilePath, format: .pem)
        let cert2 = try NIOSSLCertificate(file: SSLCertificateTest.pemCertFilePath, format: .pem)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
        XCTAssertNotEqual(cert1, SSLCertificateTest.dynamicallyGeneratedCert)
        XCTAssertNotEqual(cert1.hashValue, SSLCertificateTest.dynamicallyGeneratedCert.hashValue)
    }

    func testLoadingDerCertFromFile() throws {
        let cert1 = try NIOSSLCertificate(file: SSLCertificateTest.derCertFilePath, format: .der)
        let cert2 = try NIOSSLCertificate(file: SSLCertificateTest.derCertFilePath, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
        XCTAssertNotEqual(cert1, SSLCertificateTest.dynamicallyGeneratedCert)
        XCTAssertNotEqual(cert1.hashValue, SSLCertificateTest.dynamicallyGeneratedCert.hashValue)
    }

    func testDerAndPemAreIdentical() throws {
        let cert1 = try NIOSSLCertificate(file: SSLCertificateTest.pemCertFilePath, format: .pem)
        let cert2 = try NIOSSLCertificate(file: SSLCertificateTest.derCertFilePath, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingPemCertFromMemory() throws {
        let cert1 = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        let cert2 = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testPemLoadingMechanismsAreIdentical() throws {
        let cert11 = try NIOSSLCertificate.fromPEMBytes(.init(samplePemCert.utf8))
        let cert12 = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)

        XCTAssertEqual(cert11, [cert12])
        XCTAssertEqual(cert11.map { $0.hashValue }, [cert12.hashValue])
    }

    func testLoadingPemCertsFromMemory() throws {
        let certs1 = try NIOSSLCertificate.fromPEMBytes(.init(samplePemCerts.utf8))
        let certs2 = try NIOSSLCertificate.fromPEMBytes(.init(samplePemCerts.utf8))

        XCTAssertEqual(certs1.count, 2)
        XCTAssertEqual(certs1, certs2)
        XCTAssertEqual(certs1.map { $0.hashValue }, certs2.map { $0.hashValue })
    }

    func testLoadingPemCertsFromFile() throws {
        let certs1 = try NIOSSLCertificate.fromPEMFile(SSLCertificateTest.pemCertsFilePath)
        let certs2 = try NIOSSLCertificate.fromPEMFile(SSLCertificateTest.pemCertsFilePath)

        XCTAssertEqual(certs1.count, 2)
        XCTAssertEqual(certs1, certs2)
        XCTAssertEqual(certs1.map { $0.hashValue }, certs2.map { $0.hashValue })
    }

    func testLoadingDerCertFromMemory() throws {
        let certBytes = [UInt8](sampleDerCert)
        let cert1 = try NIOSSLCertificate(bytes: certBytes, format: .der)
        let cert2 = try NIOSSLCertificate(bytes: certBytes, format: .der)

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
    }

    func testLoadingGibberishFromMemoryAsPemFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]
        
        XCTAssertThrowsError(try NIOSSLCertificate(bytes: keyBytes, format: .pem)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromPEMBufferFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]
        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMBytes(keyBytes)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        XCTAssertThrowsError(try NIOSSLCertificate(bytes: keyBytes, format: .der)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsPemFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }
        
        XCTAssertThrowsError(try NIOSSLCertificate(file: tempFile, format: .pem)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromPEMFileFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMFile(tempFile)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsDerFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLCertificate(file: tempFile, format: .der)) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingNonexistentFileAsPem() throws {
        XCTAssertThrowsError(try NIOSSLCertificate(file: "/nonexistent/path", format: .pem)) {error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testLoadingNonexistentPEMFile() throws {
        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMFile("/nonexistent/path")) {error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingNonexistentFileAsDer() throws {
        XCTAssertThrowsError(try NIOSSLCertificate(file: "/nonexistent/path", format: .der)) {error in
            XCTAssertEqual(ENOENT, (error as? IOError).map { $0.errnoCode })
        }
    }

    func testEnumeratingSanFields() throws {
        var v4addr = in_addr()
        var v6addr = in6_addr()
        precondition(inet_pton(AF_INET, "192.168.0.1", &v4addr) == 1)
        precondition(inet_pton(AF_INET6, "2001:db8::1", &v6addr) == 1)

        let expectedSanFields: [NIOSSLCertificate.AlternativeName] = [
            .dnsName(Array("localhost".utf8)),
            .dnsName(Array("example.com".utf8)),
            .ipAddress(.ipv4(v4addr)),
            .ipAddress(.ipv6(v6addr)),
        ]
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let sans = [NIOSSLCertificate.AlternativeName](cert.subjectAlternativeNames()!)

        XCTAssertEqual(sans.count, expectedSanFields.count)
        for index in 0..<sans.count {
            switch (sans[index], expectedSanFields[index]) {
            case (.dnsName(let actualName), .dnsName(let expectedName)):
                XCTAssertEqual(actualName, expectedName)
            case (.ipAddress(.ipv4(var actualAddr)), .ipAddress(.ipv4(var expectedAddr))):
                XCTAssertEqual(memcmp(&actualAddr, &expectedAddr, MemoryLayout<in_addr>.size), 0)
            case (.ipAddress(.ipv6(var actualAddr)), .ipAddress(.ipv6(var expectedAddr))):
                XCTAssertEqual(memcmp(&actualAddr, &expectedAddr, MemoryLayout<in6_addr>.size), 0)
            default:
                XCTFail("Invalid entry in sans.")
            }
        }
    }

    func testNonexistentSan() throws {
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        XCTAssertNil(cert.subjectAlternativeNames())
    }

    func testCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        XCTAssertEqual([UInt8]("robots.sanfransokyo.edu".utf8), cert.commonName()!)
    }

    func testCommonNameForGeneratedCert() throws {
        XCTAssertEqual([UInt8]("localhost".utf8), SSLCertificateTest.dynamicallyGeneratedCert.commonName()!)
    }

    func testMultipleCommonNames() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiCNCert.utf8), format: .pem)
        XCTAssertEqual([UInt8]("localhost".utf8), cert.commonName()!)
    }

    func testNoCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(noCNCert.utf8), format: .pem)
        XCTAssertNil(cert.commonName())
    }

    func testUnicodeCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(unicodeCNCert.utf8), format: .pem)
        XCTAssertEqual([UInt8]("straße.org".utf8), cert.commonName()!)
    }

    func testExtractingPublicKey() throws {
        let cert = try assertNoThrowWithValue(NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem))
        let publicKey = try assertNoThrowWithValue(cert.extractPublicKey())
        let spkiBytes = try assertNoThrowWithValue(publicKey.toSPKIBytes())

        XCTAssertEqual(spkiBytes, sampleDerCertSPKI)
    }

    func testDumpingPEMCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }

    func testDumpingDERCert() throws {
        let expectedCertBytes = [UInt8](sampleDerCert)
        let cert = try assertNoThrowWithValue(NIOSSLCertificate(bytes: expectedCertBytes, format: .der))
        let certBytes = try assertNoThrowWithValue(cert.toDERBytes())

        XCTAssertEqual(certBytes, expectedCertBytes)
    }
}
