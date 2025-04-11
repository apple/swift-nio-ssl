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

// This class allows us to work around an awkward bug with our static below.
// We need to mark this type non-Sendable.
#if !canImport(Darwin)
final class SecCertificate {

}

@available(*, unavailable)
extension SecCertificate: Sendable {}
#endif

extension SecurityFrameworkVerificationTests {
    /// If tests fail because of an expired cert, you can regenerate the leaf and intermediate certificates
    /// by running the following command, and replacing both served certificates as leaf and intermediate,
    /// in that order:
    /// `openssl s_client -connect www.apple.com:443 -servername www.apple.com -showcerts`
    #if compiler(>=5.10)
    nonisolated(unsafe) fileprivate static let appleComCertChain: [SecCertificate] = buildAppleComCertChain()
    #else
    fileprivate static let appleComCertChain: [SecCertificate] = buildAppleComCertChain()
    #endif

    fileprivate static func buildAppleComCertChain() -> [SecCertificate] {
        #if canImport(Darwin)
        // All certs here are PEM format, with the leading/trailing lines stripped.
        let leaf = """
            MIIHezCCBmOgAwIBAgIQdBPCMTNJmIlbB9vLs/QpFTANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMiAtIEcxMB4XDTI1MDMwNDIxMjQw
            MVoXDTI1MTAxNjE3MTUzNVowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEA1n37ixRj9LjqigVGUUATnvrIg2nt0r+I1FDoZHbSUYtEhzmX
            NgiOKiQFPiDsOTlRGmFanyOKW0dkDyCd+IZ71x7eeqgPOgsht/sT9JRdZYiw2wpV
            jteioshpqyqCoPeo9gnA6L+0kvWOR8ZsNI9HhnT4zi5N7ihjtpzFyAO7vsIawAGw
            i9VmR2G8qOCuIcjC5AJ2QZWO3IF3KVWqd6r6axlmi3PcHM/rfmAmDf7ec4wAvmoz
            7u5g9uJI4G+uWwa7zeyQRldnfddSflUNeYJ5Cuxmyy1vJQvSiarzzL6hBJTQDn/W
            +ctiPw/TEHFCxp6Vm1k6v2BYV1VpOoAN5/j/fwIDAQABo4ID1jCCA9IwDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBRQVatDoa+pSCtawaKHiQTkeg7K2jB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2EyZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMmcxMDEwPAYDVR0RBDUwM4IQaW1hZ2VzLmFwcGxlLmNv
            bYIQd3d3LmFwcGxlLmNvbS5jboINd3d3LmFwcGxlLmNvbTBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMmcxLmNybDAdBgNVHQ4EFgQU38kXvF6NqC+aP2gQDzcwnAwB3ocw
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH3BgorBgEEAdZ5AgQC
            BIIB5wSCAeMB4QB1ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvlhiY6AAAB
            lWMUe6YAAAQDAEYwRAIgakiog/I40Z13f5f6IthignRanXqNvIu00nkBPm7EUi8C
            IFA1NHpLVrtYiu9UXxPH4HR8u9YLZjkmhpuSh4ArgpaTAHcAfVkeEuF4KnscYWd8
            Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGVYxR7ygAABAMASDBGAiEA/lu+9dXkosw2
            pUPmZs9elj9cjHQ53XFZafUkQ9Xrft4CIQCSGYR1zk38sMs5TdShnER/Pv5zsxCm
            j3+5KMc27lmtkQB2AObSMWNAd4zBEEEG13G5zsHSQPaWhIb7uocyHf0eN45QAAAB
            lWMUe6wAAAQDAEcwRQIgLm10XAKiyjdiEaQVvlqYVaL1blkmqzQHWcEYk+npUGoC
            IQCgY0/D6Q7woR/g4Amr8TaG34q8TQvv0kDF13cPWb/p8gB3AA3h8jAr0w3BQGIS
            CepVLvxHdHyx1+kw7w5CHrR+Tqo0AAABlWMUe6YAAAQDAEgwRgIhAIpo9UxDxijZ
            QkOxf5x9F5taXk3PdT1TU4/PJWeCqckjAiEAqwbDERS4ISdPfH15C7p+qhrbCdgW
            qitm18Ugg9adRLAwDQYJKoZIhvcNAQELBQADggEBAAsOh+VW8u4LZph6c2AYo4wS
            tNQmOFGrhqE3BB1pGK6R5J+xldygfRs571V6mkcEARqcLO7/qDHsoSpINmPLSpNg
            aPGSE9dOOc48tH2hH2z2YGyTxHh1NTPHbHkg6wqE/kKDG77gOZvHaoEligbYzC0a
            6QaD9WYTIVXDuwBJ6dSt4fbmtrReG6LY/r9c/McAUlfWY0/9jxw8Y28bJn4VQHR/
            EBKNAHnrfLMw1Basb3j/Qj6tgJaATn7ywpZ++rD4J2FydGAo9NM5dh0iqCkXA6pn
            nY8F5Z+RF7bt4H+O0uO0HywJZkI9Hh+p8QOyCS8V7qdeH7/tO9XN2GV80bn9/tI=
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
        #else
        return []
        #endif
    }
}
