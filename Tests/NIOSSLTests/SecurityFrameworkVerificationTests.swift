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
    nonisolated(unsafe) fileprivate static let appleComCertChain: [SecCertificate] = buildAppleComCertChain()

    fileprivate static func buildAppleComCertChain() -> [SecCertificate] {
        #if canImport(Darwin)
        // All certs here are PEM format, with the leading/trailing lines stripped.

        // Not Valid Before: 11 Sep 2025 18:37:53 GMT
        // Not Valid After: 18 Mar 2026 19:05:15 GMT
        let leaf = """
            MIIHejCCBmKgAwIBAgIQa1mxOs8ltXgPIYFXuZ6CtDANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMSAtIEcxMB4XDTI1MDkxMTE4Mzc1
            M1oXDTI2MDMxODE5MDUxNVowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEA3FYHDgJ3x/g6l3wPpFaNjWQmOH0Vlwfbao/ffmVNzBa6j4R/
            Z8GsNcdGg5XbweX/S1YMMqS2up9VWVp/EVtoWDi9bXnAef+JzdLHCrpj1+3YlYdC
            GoRMBwW14k7s6IO63XaPx53rEVnGu4kUVj8Pz7oWuRNalausVSFXakBX64uZJ3hQ
            J5HgjF8jt2D1qxJ4ve4HmSPQPvZDvYEhTAUyA85HzV3sfLM87IUcaJTasSFAZSgA
            PcOZrfsxQr0exRcH0nQi2ypiwp26LmFIlunsDqO6Kn9kK0HG036BuA+O1wNzuoHQ
            TzLFx6vg8MCoWhcQ95a2Ah3arGRvvblbqBj1EQIDAQABo4ID1TCCA9EwDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBTTvcE8oM81uTTF1NvaEA5M3mr+WDB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2ExZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMWcxMDEwPAYDVR0RBDUwM4INd3d3LmFwcGxlLmNvbYIQ
            aW1hZ2VzLmFwcGxlLmNvbYIQd3d3LmFwcGxlLmNvbS5jbjBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMWcxLmNybDAdBgNVHQ4EFgQUiyWALJ17vAFASOViyZgWXd1Rghww
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH2BgorBgEEAdZ5AgQC
            BIIB5gSCAeIB4AB3AGQRxGykEuyniRyiAi4AvKtPKAfUHjUnq+r+1QPJfc3wAAAB
            mTobBrwAAAQDAEgwRgIhAKYKSc9Zz/ndVyqkmtDoRAEO2N4OSP88hb/jHNeffm91
            AiEAz6uiUSxp1BL5T6gSYvfqBLOQta5lgIqOHno4X/28cggAdgAOV5S8866pPjMb
            LJkHs/eQ35vCPXEyJd0hqSWsYcVOIQAAAZk6GwapAAAEAwBHMEUCIHfywSn6ASVL
            rcZncAfSmWiLMFg/QOIpZSd2pTICENPhAiEAlLvuImUhQQ01Sm4c3hsUY7TdI50v
            +K/XIsYvHN+V22AAdQBWbNWjdr6D3+NCtnXEnCMkmKdpusOCy6tJo4d9mrMtAQAA
            AZk6GwbnAAAEAwBGMEQCIGnca087lWFs/F0jq+cynJcUmKAYAK9R+vcnv8PudfPZ
            AiBEwwyBWTPM+vvW+ZIj+DdquDglit98ctmPHNlZqUe3FwB2AEmcm2neHXzs/Dbe
            zYdkprhbrwqHgBnRVVL76esp3fjDAAABmTobBp0AAAQDAEcwRQIhALn8BHcR0+KX
            S7k29EDYPh99CT75qdYnYd13qsLVflXwAiBQnQlimOIOz5ukD2o23+7jk2yRANRE
            yqARgIVRdbimRTANBgkqhkiG9w0BAQsFAAOCAQEAmA0e6ugj7v/lcz4oo7o5aSEX
            DFrhKSRKMRKZkyiVSGytG1zEkW4IT7phNYluHoXfNqb/G5396Y9pePpa2uF/uDAu
            sF2CLxngvjtsp6EGviQQ93tcAc2xjMHZZ4kMOKaV+O2Rc3TdXcXxOUN1up2N4B1S
            9P4CVMphirwD1iBDssxQ18ScNgAfrwEElR/wGblYmIOYM4vnECs7ZVdHHGsjvnDi
            UHad1eyLC/ErPENhNqneZ7HE2Qm1PMzzfclZBYfOHb7zirTV3LECSGS25Kv8B9pu
            WxS3EtKTXc+zpbc2fbG4d9zdAzMzQrS8hYcrdCnaI50dX6AUrCpU27ObH5KeUg==
            """

        // Not Valid Before: 29 Apr 2020 12:55:34 GMT
        // Not Valid After: 11 Apr 2030 23:59:59 GMT
        let intermediate = """
            MIIFHjCCBAagAwIBAgIQBPIuzCH8tDgqwouPLWQfwDANBgkqhkiG9w0BAQsFADBh
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
            MjAeFw0yMDA0MjkxMjU1MzRaFw0zMDA0MTAyMzU5NTlaMFExCzAJBgNVBAYTAlVT
            MRMwEQYDVQQKEwpBcHBsZSBJbmMuMS0wKwYDVQQDEyRBcHBsZSBQdWJsaWMgRVYg
            U2VydmVyIFJTQSBDQSAxIC0gRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
            AoIBAQDfn5fdV0A4cCNFu0EvUgduZVPyPZity4q8Re1TcE9qGyWoVpzHm9OluDlq
            wcvudbLwBe25PWA2Z9xFpVKK9jGW6Vt79N7if7dfi9w2+2zG+/wJu1Z6TA8RENTV
            uJTaMwqQXw1dTkZEOgjCEKa75uyzXl+mIa0s4GdxkCBclGI9WDsUFlLj3A6eBIze
            TomTl7LhIV+nQUEWTqkwG5Pcxckiv7Xn1mu7EVWUukZWY8uL+KhcTJQZYtxNj3Pe
            M73WZ3fraixPA+RBkVnG5NgObRnrk5VHwjntbit9892kp7EISZK4Izfm99QgP4V2
            IqHFsKxfCnZqfwUHikxftIVkjXIdAgMBAAGjggHgMIIB3DAdBgNVHQ4EFgQU073B
            PKDPNbk0xdTb2hAOTN5q/lgwHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYX
            jzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
            AjASBgNVHRMBAf8ECDAGAQH/AgEAMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcw
            AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEIGA1UdHwQ7MDkwN6A1oDOGMWh0
            dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMi5jcmww
            gdwGA1UdIASB1DCB0TCBxQYJYIZIAYb9bAIBMIG3MCgGCCsGAQUFBwIBFhxodHRw
            czovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGKBggrBgEFBQcCAjB+DHxBbnkgdXNl
            IG9mIHRoaXMgQ2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0
            aGUgUmVseWluZyBQYXJ0eSBBZ3JlZW1lbnQgbG9jYXRlZCBhdCBodHRwczovL3d3
            dy5kaWdpY2VydC5jb20vcnBhLXVhMAcGBWeBDAEBMA0GCSqGSIb3DQEBCwUAA4IB
            AQBD9c6SmtMxGjRwc/A1bPiM+r1qj5xbDzGn6s6m6oggm9UeBLCSUNJthKffNPqq
            wtULeeUddssewaOZX+uHjG9bY/O9J1VQtGtXI2hndyAPiloqNjf5iBW16h3ZIUFQ
            L319hISioItFVJZnVe4gjNEWio1ZRwO5A4e/H69/lPAX294yGtYGllAdv2NexhUM
            fjODhCajoTJmkXbyIpYzTNkgDXvQptTecrvr0rPzEMWfTtGSppbOC+s/5jG3aJ6G
            Jn49Ram1ZLEGHTx9PWUoHth9Lj7vwFBD9667x9m9nUhuET9a3XvNep+N7w96ZqH2
            fAqUBW1kl6u3u67D6mvDsCQr
            """

        return [leaf, intermediate].map {
            SecCertificateCreateWithData(nil, Data(base64Encoded: $0, options: .ignoreUnknownCharacters)! as CFData)!
        }
        #else
        return []
        #endif
    }
}
