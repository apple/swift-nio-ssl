//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import XCTest

@testable import NIOSSL

// We can only use Security.framework to validate TLS certificates on Apple platforms.
#if canImport(Darwin)
import Dispatch
import Foundation
import Security
import NIOPosix
#endif

final class SecurityFrameworkVerificationTests: XCTestCase {
    static let selfSignedCert: NIOSSLCertificate = {
        generateSelfSignedCert().0
    }()

    static let anotherSelfSignedCert: NIOSSLCertificate = {
        generateSelfSignedCert().0
    }()

    func testDefaultVerification() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)
        let context = try NIOSSLContext(configuration: .makeClientConfiguration())
        let connection = context.createConnection()!
        connection.setConnectState()

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: Self.appleComCertChain)
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .certificateVerified)
        #endif
    }

    func testDefaultVerificationCanFail() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)
        let context = try NIOSSLContext(configuration: .makeClientConfiguration())
        let connection = context.createConnection()!
        connection.setConnectState()

        let certificate = SecCertificateCreateWithData(nil, Data(try! Self.selfSignedCert.toDERBytes()) as CFData)!

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: [certificate])
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .failed)
        #endif
    }

    func testDefaultVerificationCanValidateHostname() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)
        let context = try NIOSSLContext(configuration: .makeClientConfiguration())
        let connection = context.createConnection()!
        connection.setConnectState()
        connection.expectedHostname = "www.apple.com"

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: Self.appleComCertChain)
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .certificateVerified)
        #endif
    }

    func testDefaultVerificationFailsOnInvalidHostname() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)
        let context = try NIOSSLContext(configuration: .makeClientConfiguration())
        let connection = context.createConnection()!
        connection.setConnectState()
        connection.expectedHostname = "www.swift-nio.io"

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: Self.appleComCertChain)
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .failed)
        #endif
    }

    func testDefaultVerificationIgnoresHostnamesWhenConfiguredTo() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .noHostnameVerification
        let context = try NIOSSLContext(configuration: configuration)
        let connection = context.createConnection()!
        connection.setConnectState()
        connection.expectedHostname = "www.swift-nio.io"

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: Self.appleComCertChain)
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .certificateVerified)
        #endif
    }

    func testDefaultVerificationPlusAdditionalCanUseAdditionalRoot() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)

        var config = TLSConfiguration.makeClientConfiguration()
        config.additionalTrustRoots = [.certificates([Self.selfSignedCert])]
        let context = try NIOSSLContext(configuration: config)
        let connection = context.createConnection()!
        connection.setConnectState()

        let certificate = SecCertificateCreateWithData(nil, Data(try! Self.selfSignedCert.toDERBytes()) as CFData)!

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: [certificate])
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .certificateVerified)
        #endif
    }

    func testDefaultVerificationPlusAdditionalCanUseDefaultRoots() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)

        var config = TLSConfiguration.makeClientConfiguration()
        config.additionalTrustRoots = [.certificates([Self.selfSignedCert])]
        let context = try NIOSSLContext(configuration: config)
        let connection = context.createConnection()!
        connection.setConnectState()

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: Self.appleComCertChain)
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .certificateVerified)
        #endif
    }

    func testDefaultVerificationPlusAdditionalCanFailWithUnknownCert() throws {
        #if canImport(Darwin)
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try! group.syncShutdownGracefully()
        }

        let p = group.next().makePromise(of: NIOSSLVerificationResult.self)

        var config = TLSConfiguration.makeClientConfiguration()
        config.additionalTrustRoots = [.certificates([Self.selfSignedCert])]
        let context = try NIOSSLContext(configuration: config)
        let connection = context.createConnection()!
        connection.setConnectState()

        let certificate = SecCertificateCreateWithData(
            nil,
            Data(try! Self.anotherSelfSignedCert.toDERBytes()) as CFData
        )!

        connection.performSecurityFrameworkValidation(promise: p, peerCertificates: [certificate])
        let result = try p.futureResult.wait()

        XCTAssertEqual(result, .failed)
        #endif
    }
}

#if canImport(Darwin)
extension SecurityFrameworkVerificationTests {
    /// If tests fail because of an expired cert, you can regenerate the leaf and intermediate certificates
    /// by running the following command, and replacing both served certificates as leaf and intermediate,
    /// in that order:
    /// `openssl s_client -connect www.apple.com:443 -servername www.apple.com -showcerts`
    static let appleComCertChain: [SecCertificate] = {
        // All certs here are PEM format, with the leading/trailing lines stripped.
        let leaf = """
            MIIHezCCBmOgAwIBAgIQfrZYqgaHdOKdEb5ZVqa0LTANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMiAtIEcxMB4XDTI0MTIwOTE3NTcw
            NFoXDTI1MDQwODE5NTY1NlowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAxlSqT8ZVN6y8/a3TDdV9zwNyhjeCH7AEckmzN810eAKJ/079
            QHFI+5KisoP9Uuu0W/dWO/NVFSH6cf6zA6I1qvewAkkaocJETuO+OKosPXWZpAGF
            UcoT1j098EQy2OCLD5DfYYGYZDIFqGzGw9jgxAfuMcIcPmHn0PbS6wX/ePTze5kF
            zNTlc5//w+UtIGHi3QP327Urzyi2rjIGOWBjjKDdvqdYQl+7Sv1QKKBZpWlinNqe
            5POugwkOYQLbE3MwjaVDN/iF7CE005avSxPo4G8vNKaq9VGdQuJb0qzI1M2gTD9G
            86oeFh5AZ0/erTAe+NshueHXK3tX13JLNjodlwIDAQABo4ID1jCCA9IwDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBRQVatDoa+pSCtawaKHiQTkeg7K2jB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2EyZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMmcxMDEwPAYDVR0RBDUwM4IQd3d3LmFwcGxlLmNvbS5j
            boINd3d3LmFwcGxlLmNvbYIQaW1hZ2VzLmFwcGxlLmNvbTBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMmcxLmNybDAdBgNVHQ4EFgQURk32jbOK8tOTKUM09x18GFD6T6Mw
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH3BgorBgEEAdZ5AgQC
            BIIB5wSCAeMB4QB3AH1ZHhLheCp7HGFnfF79+NCHXBSgTpWeuQMv2Q6MLnm4AAAB
            k6yafEsAAAQDAEgwRgIhAOb4XXNkF7XCVLpkJYYXdIKiD+Tziy4e0v4d+0dqXSZi
            AiEA5pyC6BSpmzVasV2UZLgc5Efc/JrvEJsA8gGQyeDcKZQAdgDM+w9qhXEJZf6V
            m1PO6bJ8IumFXA2XjbapflTA/kwNsAAAAZOsmnxzAAAEAwBHMEUCIQDgvdW/qcpk
            s4kJ8s0p3L+Dbk2oFW8WoX6Y0QTbQZ3AqAIgQKsyTTgEX7+nBebYXO9P95TnNFfZ
            zZ8j6O3yNNBTZh4AdgBOdaMnXJoQwzhbbNTfP1LrHfDgjhuNacCx+mSxYpo53wAA
            AZOsmnxNAAAEAwBHMEUCIG5b5kcJPYmr4IYZaC0YpHwUv+qbZz8D8+PPxsfu8nGa
            AiEA/gFI1QZrlKSxFWnzLVNJxbnSfUxK78RfvmzAUJTu9poAdgDgkrP8DB3I52g2
            H95huZZNClJ4GYpy1nLEsE2lbW9UBAAAAZOsmnxnAAAEAwBHMEUCIQCz0KgSqiTL
            e9nviiPOBcnKhvfyN33UpL6gx2Ot9NF6oAIgUgLXXf+hys90XZnVumvz5omAQ8zK
            1iSzkLtwGaJx6dIwDQYJKoZIhvcNAQELBQADggEBAGZWm3BMjUDhPBgvkopxXuQr
            eRAzJmEWlD+cJdoHFYhsdfTSIbSvO3kEsKoBzxVZPeDopZTTfqH+XLDHu46HCXYL
            UjEmHZi3gwd93cu8WytJc0O3Vb9HbeSChgMi7q4zcNpzqYS9m6+z4sD6I3hCVV8i
            v7dqoZulTh1g9MD9bOql9eEW8LvryY6qu8JeDuha/eYU6lGJwleS/MTE0gr+TxmY
            6N0bv7xYtSlEBLXSElz7VFcq7GqsrApEqoVkk24oOpfQ4xeEDhvulyDtEOW0DT8D
            l+UjuDVM264DL03VGGv1bidxXqf1ZtsLYiVfIFz+7GNj9xjKL+6JR7ir/XGGvyY=
            """

        let intermediate = """
            MIIFMjCCBBqgAwIBAgIQBxd5EQBdImf2iJL2j4tQWDANBgkqhkiG9w0BAQsFADBs
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
            ZSBFViBSb290IENBMB4XDTIwMDQyOTEyNTQ1MFoXDTMwMDQxMDIzNTk1OVowUTEL
            MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xLTArBgNVBAMTJEFwcGxl
            IFB1YmxpYyBFViBTZXJ2ZXIgUlNBIENBIDIgLSBHMTCCASIwDQYJKoZIhvcNAQEB
            BQADggEPADCCAQoCggEBAOIA/aXfX7k4cUnrupPYw00z3FwU6nAvwepTO8ueUcBU
            smQGppcx5BeEyngvZ8PSieH0GHHK7RnHbgLChyon2H9EpgYo7NQ1yrcC5THvo3Vr
            lAP6U746ORSDxUbbv4z15kAsyvABUCFi8S7IXkzDIjhOICNrA8fXUpUKbIccI2Jv
            Mz7Rvw5GeG7caa2u+vSI3TmBnwMcjVqlsScqY6tbE/ji7C/XDw7wUpMHyaQMVGPO
            7mJfi0/QbiUPWwnCJPYAqPpvBVjeBh0avUCGaP2ZtZc2Jns1C8h9ebJG+Z3awdgB
            qQPYD2I+fy/aBtnTOkhnBJti8jxh1ThNV65S9SucZecCAwEAAaOCAekwggHlMB0G
            A1UdDgQWBBRQVatDoa+pSCtawaKHiQTkeg7K2jAfBgNVHSMEGDAWgBSxPsNpA/i/
            RwHUmCYaCALvY2QrwzAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH
            AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAm
            MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSwYDVR0fBEQw
            QjBAoD6gPIY6aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFz
            c3VyYW5jZUVWUm9vdENBLmNybDCB3AYDVR0gBIHUMIHRMIHFBglghkgBhv1sAgEw
            gbcwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgYoG
            CCsGAQUFBwICMH4MfEFueSB1c2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb25zdGl0
            dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBSZWx5aW5nIFBhcnR5IEFncmVlbWVudCBs
            b2NhdGVkIGF0IGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9ycGEtdWEwBwYFZ4EM
            AQEwDQYJKoZIhvcNAQELBQADggEBAKZebFC2ZVwrTj+u6nDo3O03e0/g/hN+6U5i
            A7X9dBGmQx3C7NkPNAV0mUoaklsceIBIQ/bC7utdgwnSKTnm5HdVipASyLloU7TP
            2jAtDQdAxBavmLnFwcwXBp6n17uLp+uPU4DZgubM96LyUQilUlYERbgu66rCK18j
            RmobDvFT8E71oU13o1Oe/1WUHFbTynRkKW73JDd2rZ21Pim7LEJVY3OcRmtYNHaM
            /lunYx1ZQ+0fw7Hc5J/xR7vlRiuyP+fJ9ucuDYupLg333Di5R7JZIfnX42ecX0Dd
            0wIeuFj0HBjH6c25FUov/Fa5Zjr0VPjmmgN6PnoMArUZXDkQe3M=
            """

        return [leaf, intermediate].map {
            SecCertificateCreateWithData(nil, Data(base64Encoded: $0, options: .ignoreUnknownCharacters)! as CFData)!
        }
    }()
}
#endif
