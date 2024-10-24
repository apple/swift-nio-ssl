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
            MIIHejCCBmKgAwIBAgIQFEfPshq/qaj2Zf8Y/vVgUjANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMiAtIEcxMB4XDTI0MDgyMzE3MzAx
            MVoXDTI0MTEyMTE3NDAxMVowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAyKICisEcp5ruWEmbEDxBjb/vbyN+ZAXpuSBXOzZbntL5ZN75
            Wq+ELBDBCNHs5NJ01x4rw7rEF36xyJ9dNBvjyAb5yNu7w68WRmoEIlTIFC1DYSHs
            xNWU/7ot305j/p12v6yqSco7pCUfi1JrYeqd8oBXYrJauzUyjP96dT9L+7l3wKm6
            jbS0NbG62C6W4bcHxdq5UPTIVJDjqibZekMfYnM/iOtctx/SdCvHOdBzyl1Ks0tZ
            ItFUxUHfpqXBKjnFMUg5g+rqLXc7UUSSr6Z5Ro6Cju+wPWsUvxZ0QAkvvBmlIY21
            vDUsUQv7ZsaiJFY4WO6Y+zu3KZVONu4N8mPQCQIDAQABo4ID1TCCA9EwDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBRQVatDoa+pSCtawaKHiQTkeg7K2jB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2EyZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMmcxMDEwPAYDVR0RBDUwM4INd3d3LmFwcGxlLmNvbYIQ
            aW1hZ2VzLmFwcGxlLmNvbYIQd3d3LmFwcGxlLmNvbS5jbjBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMmcxLmNybDAdBgNVHQ4EFgQUnYQjfWyYxNohSZQiCR7oNyhsduEw
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH2BgorBgEEAdZ5AgQC
            BIIB5gSCAeIB4AB2AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAAB
            kYBTDJsAAAQDAEcwRQIhAPYW1NYvfxVjbeLuVetuXlyZLDNKNNOPk/DIDP/ulW+s
            AiBjNexLcU6HvsVJSsk9SXpuCgMeKE942dmBUsmNH1PgCwB3ANq2v2s/tbYin5vC
            u1xr6HCRcWy7UYSFNL2kPTBI1/urAAABkYBTDN4AAAQDAEgwRgIhAN8y6nBmFFjB
            6Wr3QZErziopyOpqztPnegAgXGLKWgzyAiEA53yPV9KHRJRemZ1btzY7+Ds7tUF3
            e3s52DGzGTEgiVQAdgDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlGcR+1mwAA
            AZGAUwzFAAAEAwBHMEUCIByK/3OO2g8iokkvPO2uTKZukPRRhb9ZPwu4rd2oO9Sm
            AiEAr9R7HVz3UBZuVwjcHv9LKWqoQ5Z0l0Pb5YyPZ17h9kcAdQAZmBBxCfDWUi4w
            gNKeP2S7g24ozPkPUo7u385KPxa0ygAAAZGAUw0EAAAEAwBGMEQCICJs0tMQ5cUk
            FXHGCIpX33RL9JqehQT34oqiSpSIBLSOAiAyWdjUUleeq7yqRElesURod3KSwPM+
            +97hFsjxFaZLQjANBgkqhkiG9w0BAQsFAAOCAQEATLPqosjajvXRJ4V9fwb1XMDS
            X4gCGKqdcso2q7C8kDTHUCduu4B0S/phIbJE+TrtjHaNwGO8oZG2rt9u7XQvnisr
            ZwR5nAZMaW7MggsugWkhxl+DThbSJXZSwd44gn9+HjrNJkqdn+R07qxGdqe4io2b
            eWY1KfY8ZFFkhSVtaQvEb0LjHh/YSi0UzUuaKIHyuwzQKE/3OFZkSsVaA4hxuJ0o
            MPPVehmcin4dY7PEtOZYTcUmOfW3Nv+cdgjj84tH5urSbqN0CdaOG4xdCDqMhFgX
            aIL2NGfQMTmPV6jCeOpm/8B/XoaD/rufYyfyI9H79vSwQQz9qoSy9D5dzNXvsA==
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
