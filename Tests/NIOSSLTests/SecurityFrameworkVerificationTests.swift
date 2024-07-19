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

        let certificate = SecCertificateCreateWithData(nil, Data(try! Self.anotherSelfSignedCert.toDERBytes()) as CFData)!

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
            MIIHfDCCBmSgAwIBAgIQATyyJFiUVZ8X5Gj1MTLNCDANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMiAtIEcxMB4XDTI0MDYyMDE5MTI0
            NVoXDTI0MDkxODE5MjI0NVowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAoZMSzyh9Kc89VO0rbdBwczEYq/vVCFstY4wfqwM5Ujw22hER
            Ao68GIkowTmNEoPCExbYqZPOBkTU7PD8VDV/7Dz8vvvBfPc2eWaRbuabOjATNQIx
            bi5k+mbKTbr1+lg33FEKzeFonSYkL6kqD6Nf54xRPoXa9kNYQeuwtUZtg4xMxNh8
            46LnbXt0HdgIHJ60TgLxnhYQtFocltz+kJUlzQmPf4fS77xtc35caFk79kMw9zxd
            R6G9l9u/TR3PsgI9+zjS23/K4z0/quW/uwr5dILIG1F5HQ6xr0PreskMxd087mVy
            2q0tfkWN4+a7krs1xP/bQHwjVgz9mgI5E2GVJQIDAQABo4ID1zCCA9MwDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBRQVatDoa+pSCtawaKHiQTkeg7K2jB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2EyZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMmcxMDEwPAYDVR0RBDUwM4IQaW1hZ2VzLmFwcGxlLmNv
            bYIQd3d3LmFwcGxlLmNvbS5jboINd3d3LmFwcGxlLmNvbTBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMmcxLmNybDAdBgNVHQ4EFgQUkR204uwmGTkLM8SWtwcpGJfV3asw
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH4BgorBgEEAdZ5AgQC
            BIIB6ASCAeQB4gB3AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAAB
            kDcZ9Q4AAAQDAEgwRgIhAOjsftekDAX9X2/3excjhAD/kJtsZLAyCHkjAUi3R7cg
            AiEAjNRxRI22qkHp8J/KUoxZiJgmdscawybTz9PW4ikpj9MAdwBIsONr2qZHNA/l
            agL6nTDrHFIBy1bdLIHZu7+rOdiEcwAAAZA3GfT8AAAEAwBIMEYCIQC+cIxOI9IN
            z3E6sUPoeFoUZXpWn+TO7YFivBI7wGix2gIhAJ2kPioANfCCjhYDMZ9+//6qdM18
            6/wmzHi2gqFBkoBHAHYA2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6sA
            AAGQNxn1LAAABAMARzBFAiAW/yq/wdU/xrjGGrexlMCamN6OGfWR1WGgHkkeD0z3
            7gIhAOOb4fm1m6dZmDyqVdG38aJrW4zm2QNsD3Ze7Uhg7BMEAHYA7s3QZNXbGs7F
            XLedtM0TojKHRny87N7DUUhZRnEftZsAAAGQNxn1AwAABAMARzBFAiEAviamxheQ
            he3ZCQ/LC1M/kfUUfyNR5MVPDNmQtB3xTLcCIGBdVHVIlmkzaiv441tLm5UnCAE4
            6jyAi/ZLQbfhmMPZMA0GCSqGSIb3DQEBCwUAA4IBAQC9UUM9oP39H2TcLdAVOAiY
            VyM+MOENKn2p6Akaf3D/rZqrL9AVwQEA5SsRYwALmslOXJsMXdflQLL60jnWyNaq
            WJ0UuOHAt3aB76q67Jsk+Kk3dNg4HPbu7PMvO1fBrjqd9ZIKG3m7rChoTDcean72
            4Vg+yQ2mrSRBfVdt2QK61zOyxuEYknSTLzOq/WK8xOKLYgIahqKtlh7Xr+xPeQJN
            PnhYLg5svRRpeLSnagx4eiPcnweHESkTmV3CjpJfKzAdt0gF1s8TzPpAnKmtuwcM
            98vR8IkBkBkKzkuwkC2QJcioryRWALwErYRfwWZd1RU0Du3JwSJk9Cbi+rH3UclP
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
