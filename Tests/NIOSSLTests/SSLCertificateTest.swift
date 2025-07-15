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

// created with the following command:
// openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
//   -keyout private.pem -out cert.pem -subj '/CN=example.com' \
//   -extensions san \
//   -config <(echo '[req]'; echo 'distinguished_name=req';
//             echo '[san]'; echo 'subjectAltName=DNS:localhost,DNS:example.com,email:user@example.com,IP:192.168.0.1,IP:2001:db8::1,URI:http://example.com/path?query=param,URI:http://example.org/')
let certWithAllSupportedSANTypes = """
    -----BEGIN CERTIFICATE-----
    MIIFOzCCAyOgAwIBAgIJALPXfgvEjcDsMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
    BAMMC2V4YW1wbGUuY29tMB4XDTIyMDMwOTE4MTIxN1oXDTMyMDMwNjE4MTIxN1ow
    FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
    ggIKAoICAQC7Bwqt8H+O3zotsGo4KMjipytzfmYiTOS0Id6HY1zfLVGrOSRTbFAE
    BmpPWbu4TzDZpxoNa6oQYqcpMqHTJe6+U/Coz+Xm+fSqWVZPLzcX2iW6igeS5cH5
    2C9sWbzbYJku3qiNc0B0K+sIPQLeUM8sc2UK6rL3Vc6kt/SRRjshZNj6hPRqQNv6
    85ul6yxICOooX6Xy/q0lqJaWaIOk2GZa/Genz/93RbKnLCpynSX0JETcIW8uFIPo
    3BeyFcvgThYUq/KvpkkNPqOp7SOfO5rFLi9IRlDNuUF9h4hLZ+qV3NaxQ5mk+8xl
    BcNPDNqucNwQ7UKRNEfipmVPE44txMh06VcahcSzc+FKGsQmlNON0WwMfTTRhCPD
    Y2JVKZ5BpsgUtrivC4UbNmNJEVQQ9dJBcsALuwhoJo5CL0tkI2Dx/eo6fpwL6KDu
    ZE71MZ8BSJ8fW620fGedR+Cr+Jeq5H5eGGaWw55hXRKHbOQgjvIC6LKp9CB4/wNK
    jwlWEgae/EiI7iCuSOLj+yGbWvCnUcYdzYxuxZMY1x097dXxWObzJHgHllIT8639
    LqDT7+Xrhqoe0eMxeYwHzE8VMEPPpBeZAGzYO1lXF2lWqzIaPHK2oIeNj8Rskzqd
    GFJPSvTZqEUBxgITiz5Ba46G9Cyi4oVom5CIPI+UWBLxDLjUiDbYtQIDAQABo4GL
    MIGIMIGFBgNVHREEfjB8gglsb2NhbGhvc3SCC2V4YW1wbGUuY29tgRB1c2VyQGV4
    YW1wbGUuY29thwTAqAABhxAgAQ24AAAAAAAAAAAAAAABhiNodHRwOi8vZXhhbXBs
    ZS5jb20vcGF0aD9xdWVyeT1wYXJhbYYTaHR0cDovL2V4YW1wbGUub3JnLzANBgkq
    hkiG9w0BAQsFAAOCAgEAJFzzbzD5+YGnX2cXKms9ZSqzdFyzkU1/Glc4gCJJu0ch
    GxdqRA1D9eiYtaumtnTwdN/VsJGtHQy87ur+9hawQ7MwA8E45RJoibwT/trCggzK
    gjWeor9l1ahwr4eBgmmWDzmdUXd2HcCBRR5iXfU3CLj8BUT2EXx8iFbkHHc5uZGi
    19ZfyAaWBV5KkkMjk9FMYAoFCsv/eDjtQzlfJrgKDcAZu7GD7ijYcw2buGeRl9SG
    //QKkyAVEnY2Fpn0v+pwOWBunB4EV2bRK+TbSScaU0EC3+AT9Xl62IAqJsdmTOrr
    URM7cuo6HVFLhNbAsUZMwd/orLQmKnp+njZOKdcq+J8f3aIUhKBIKg+sYcFVpV1Z
    Mpmm/M04hN+EGuZqASJRfIE1CI5PXizVd6sQd1A/zhoy9QtfbVGgxWklYgmy7ycB
    wS41t3bU8LLCC3RXflBOBz4y+/7Oe6muRWUAEXt4rgc4Zv391SfIFpwEaNOtFATl
    LzVcCAEmtY1Fyp4cOm6GEMjZ0H0buOaCRoYJb3KYZm5L6c58Ahom2GfAdtdoiRcX
    7JHZybbOiOTgThxfXxgzABq/HVLC5PNVlAk95SYcoFMjixyDt2S9JD9fnGI3H9CT
    kVuVyNH7NBMh6YOuTL1dh55bvDjvgkuzudepsZnpfjgQKE1aZ7dL32Xi000gBM8=
    -----END CERTIFICATE-----
    """

func makeTemporaryFile(fileExtension: String = "", customPath: String = "") throws -> String {
    var template = "\(FileManager.default.temporaryDirectory.path)/niotestXXXXXXX\(fileExtension)"
    // If a custom file path is passed in then a new directory has to also be created.  Then the file can be written to that directory.
    if !customPath.isEmpty {
        let path = "\(FileManager.default.temporaryDirectory.path)/\(customPath)/"
        try FileManager.default.createDirectory(at: URL(fileURLWithPath: path), withIntermediateDirectories: true)
        template = "\(FileManager.default.temporaryDirectory.path)/\(customPath)/niotestXXXXXXX\(fileExtension)"
    }
    var templateBytes = template.utf8 + [0]
    let fd = templateBytes.withUnsafeMutableBufferPointer { ptr in
        ptr.baseAddress!.withMemoryRebound(to: Int8.self, capacity: ptr.count) { (ptr: UnsafeMutablePointer<Int8>) in
            mkstemps(ptr, CInt(fileExtension.utf8.count))
        }
    }
    close(fd)
    templateBytes.removeLast()
    return String(decoding: templateBytes, as: UTF8.self)
}

internal func dumpToFile(data: Data, fileExtension: String = "", customPath: String = "") throws -> String {
    let filename = try makeTemporaryFile(fileExtension: fileExtension, customPath: customPath)
    try data.write(to: URL(fileURLWithPath: filename))
    return filename
}

internal func dumpToFile(text: String, fileExtension: String = "") throws -> String {
    try dumpToFile(data: text.data(using: .utf8)!, fileExtension: fileExtension)
}

class SSLCertificateTest: XCTestCase {
    static let dynamicallyGeneratedCert = generateSelfSignedCert().0

    private static func withPemCertPath<ReturnType>(
        _ body: (String) throws -> ReturnType
    ) throws -> ReturnType {
        let pemCertFilePath = try dumpToFile(text: samplePemCert)
        defer {
            unlink(pemCertFilePath)
        }
        return try body(pemCertFilePath)
    }

    private static func withPemCertsPath<ReturnType>(
        _ body: (String) throws -> ReturnType
    ) throws -> ReturnType {
        let pemCertsFilePath = try dumpToFile(text: samplePemCerts)
        defer {
            unlink(pemCertsFilePath)
        }
        return try body(pemCertsFilePath)
    }

    private static func withDerCertPath<ReturnType>(
        _ body: (String) throws -> ReturnType
    ) throws -> ReturnType {
        let derCertFilePath = try dumpToFile(data: sampleDerCert)
        defer {
            unlink(derCertFilePath)
        }
        return try body(derCertFilePath)
    }

    private func dateFromComponents(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int) -> Date {
        var date = DateComponents()
        date.calendar = Calendar(identifier: .gregorian)
        date.year = year
        date.month = month
        date.day = day
        date.hour = hour
        date.minute = minute
        date.second = second
        date.timeZone = TimeZone(abbreviation: "UTC")
        return date.date!
    }

    func testLoadingPemCertFromFile() throws {
        let (cert1, cert2) = try Self.withPemCertPath {
            let cert = try NIOSSLCertificate.fromPEMFile($0).first!
            return (cert, cert)
        }

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
        XCTAssertNotEqual(cert1, SSLCertificateTest.dynamicallyGeneratedCert)
        XCTAssertNotEqual(cert1.hashValue, SSLCertificateTest.dynamicallyGeneratedCert.hashValue)
    }

    func testLoadingDerCertFromFile() throws {
        let (cert1, cert2) = try Self.withDerCertPath {
            let cert = try NIOSSLCertificate.fromDERFile($0)
            return (cert, cert)
        }

        XCTAssertEqual(cert1, cert2)
        XCTAssertEqual(cert1.hashValue, cert2.hashValue)
        XCTAssertNotEqual(cert1, SSLCertificateTest.dynamicallyGeneratedCert)
        XCTAssertNotEqual(cert1.hashValue, SSLCertificateTest.dynamicallyGeneratedCert.hashValue)
    }

    func testDerAndPemAreIdentical() throws {
        let cert1 = try Self.withPemCertPath {
            try NIOSSLCertificate.fromPEMFile($0).first!
        }
        let cert2 = try Self.withDerCertPath {
            try NIOSSLCertificate.fromDERFile($0)
        }

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
        let (certs1, certs2) = try Self.withPemCertsPath {
            (
                try NIOSSLCertificate.fromPEMFile($0),
                try NIOSSLCertificate.fromPEMFile($0)
            )
        }

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

        XCTAssertThrowsError(try NIOSSLCertificate(bytes: keyBytes, format: .pem)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromPEMBufferFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]
        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMBytes(keyBytes)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromMemoryAsDerFails() throws {
        let keyBytes: [UInt8] = [1, 2, 3]

        XCTAssertThrowsError(try NIOSSLCertificate(bytes: keyBytes, format: .der)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsPemFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMFile(tempFile)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromPEMFileFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMFile(tempFile)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingGibberishFromFileAsDerFails() throws {
        let tempFile = try dumpToFile(text: "hello")
        defer {
            _ = tempFile.withCString { unlink($0) }
        }

        XCTAssertThrowsError(try NIOSSLCertificate.fromDERFile(tempFile)) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    @available(*, deprecated, message: "Deprecated to test deprecated functionality")
    func testLoadingNonexistentFileAsPem() throws {
        XCTAssertThrowsError(try NIOSSLCertificate(file: "/nonexistent/path", format: .pem)) { error in
            guard let error = error as? IOError else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertEqual(ENOENT, error.errnoCode)
            XCTAssertEqual(
                error.description.contains("/nonexistent/path"),
                true,
                "error description should contain file path. Description: \(error.description)"
            )
        }
    }

    func testLoadingNonexistentPEMFile() throws {
        XCTAssertThrowsError(try NIOSSLCertificate.fromPEMFile("/nonexistent/path")) { error in
            XCTAssertEqual(.failedToLoadCertificate, error as? NIOSSLError)
        }
    }

    func testLoadingNonexistentFileAsDer() throws {
        XCTAssertThrowsError(try NIOSSLCertificate.fromDERFile("/nonexistent/path")) { error in
            guard let error = error as? IOError else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertEqual(ENOENT, error.errnoCode)
            XCTAssertEqual(
                error.description.contains("/nonexistent/path"),
                true,
                "error description should contain file path. Description: \(error.description)"
            )
        }
    }

    func testEnumeratingSanFields() throws {
        var v4addr = in_addr()
        var v6addr = in6_addr()
        precondition(inet_pton(AF_INET, "192.168.0.1", &v4addr) == 1)
        precondition(inet_pton(AF_INET6, "2001:db8::1", &v6addr) == 1)

        let cert = try NIOSSLCertificate(bytes: .init(certWithAllSupportedSANTypes.utf8), format: .pem)
        let sans = cert._subjectAlternativeNames()
        XCTAssertEqual(sans.count, 7)
        XCTAssertEqual(sans[0].nameType, .dnsName)
        XCTAssertEqual(String(decoding: sans[0].contents, as: UTF8.self), "localhost")
        XCTAssertEqual(sans[1].nameType, .dnsName)
        XCTAssertEqual(String(decoding: sans[1].contents, as: UTF8.self), "example.com")
        XCTAssertEqual(sans[2].nameType, .email)
        XCTAssertEqual(String(decoding: sans[2].contents, as: UTF8.self), "user@example.com")
        XCTAssertEqual(sans[3].nameType, .ipAddress)
        withUnsafeBytes(of: &v4addr) { v4addr in
            XCTAssertEqual(Array(sans[3].contents), Array(v4addr))
        }
        XCTAssertEqual(sans[4].nameType, .ipAddress)
        withUnsafeBytes(of: &v6addr) { v6addr in
            XCTAssertEqual(Array(sans[4].contents), Array(v6addr))
        }
        XCTAssertEqual(sans[5].nameType, .uri)
        XCTAssertEqual(String(decoding: sans[5].contents, as: UTF8.self), "http://example.com/path?query=param")
        XCTAssertEqual(sans[6].nameType, .uri)
        XCTAssertEqual(String(decoding: sans[6].contents, as: UTF8.self), "http://example.org/")
    }

    func testSubjectName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        XCTAssertEqual(
            cert.subjectName,
            [
                SSLCertificateName("US", .country),
                SSLCertificateName("California", .state),
                SSLCertificateName("San Fransokyo", .city),
                SSLCertificateName("San Fransokyo Institute of Technology", .organization),
                SSLCertificateName("Robotics Lab", .organizationalUnit),
                SSLCertificateName("robots.sanfransokyo.edu", .commonName),
            ]
        )
    }

    func testIssuerName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(sampleIntermediateCA.utf8), format: .pem)
        XCTAssertEqual(cert.issuerName, [SSLCertificateName("badCertificateAuthority", .commonName)])
    }

    func testNonexistentSan() throws {
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        XCTAssertTrue(cert._subjectAlternativeNames().isEmpty)
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

    func testPrintingDebugDetailsNoAlternativeNames() throws {
        let expectedDebugDescription =
            "<NIOSSLCertificate;serial_number=9fd7d05a34ca7984;common_name=robots.sanfransokyo.edu>"
        let cert = try assertNoThrowWithValue(NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem))
        let debugString = String(describing: cert)

        XCTAssertEqual(debugString, expectedDebugDescription)
    }

    func testPrintingDebugDetailsWithAlternativeNames() throws {
        let expectedDebugDescription =
            "<NIOSSLCertificate;serial_number=46231a526848d57af4999e29f89988d178d94da2;common_name=localhost;alternative_names=localhost,example.com,192.168.0.1,2001:db8::1>"
        let cert = try assertNoThrowWithValue(NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem))
        let debugString = String(describing: cert)

        XCTAssertEqual(debugString, expectedDebugDescription)
    }

    func testNotValidBefore() throws {
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        let notValidBeforeSeconds = cert.notValidBefore

        let expectedDate = self.dateFromComponents(year: 2017, month: 10, day: 16, hour: 21, minute: 01, second: 02)
        let expectedSeconds = time_t(expectedDate.timeIntervalSince1970)
        XCTAssertEqual(notValidBeforeSeconds, expectedSeconds)
    }

    func testNotValidAfter() throws {
        try XCTSkipUnless(MemoryLayout<time_t>.size >= 8, "size of time_t must be 64bit or greater")
        let cert = try NIOSSLCertificate(bytes: .init(samplePemCert.utf8), format: .pem)
        let notValidBeforeSeconds = cert.notValidAfter

        let expectedDate = self.dateFromComponents(year: 2047, month: 10, day: 9, hour: 21, minute: 01, second: 02)
        let expectedSeconds = time_t(expectedDate.timeIntervalSince1970)
        XCTAssertEqual(notValidBeforeSeconds, expectedSeconds)
    }

    func testNotBeforeAfterGeneratedCert() throws {
        let notBefore = SSLCertificateTest.dynamicallyGeneratedCert.notValidBefore
        let notAfter = SSLCertificateTest.dynamicallyGeneratedCert.notValidAfter

        // Clock movement is tricky so we can't necessarily assert what the delta is in
        // the notBefore and now, but we know now has to be between the two values, and
        // that the two values are 1 hour apart.
        let secondsNow = time_t(Date().timeIntervalSince1970)
        XCTAssertTrue((notBefore..<notAfter).contains(secondsNow))
        XCTAssertEqual(notAfter - notBefore, 60 * 60)
    }
}
