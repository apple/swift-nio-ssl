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

        // Not Valid Before: 11 Feb 2026 17:44:10 GMT
        // Not Valid After: 8 Aug 2026 17:30:10 GMT
        let leaf = """
            MIIHeDCCBmCgAwIBAgIQCiKs5C/HH0Y/lT7wtag/DDANBgkqhkiG9w0BAQsFADBR
            MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBw
            bGUgUHVibGljIEVWIFNlcnZlciBSU0EgQ0EgMSAtIEcxMB4XDTI2MDIxMTE3NDQx
            MFoXDTI2MDgxODE3MzAxMFowgccxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
            aW9uMRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQIMCkNhbGlm
            b3JuaWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECAwK
            Q2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMRMwEQYDVQQKDApBcHBsZSBJ
            bmMuMRYwFAYDVQQDDA13d3cuYXBwbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAk90vvxbvjCycmnxqzhVhARxSD3lFU14ECmveg1JJkfWV2tQc
            kiQjakUx3i5o4oF5BX94TgKHfbQ4CDeNkkTdgiE8c5d1SyQ30OKMmu5Png+MBtyU
            ERTYE6789ZQSX7Qj4YeZUMnBTB0gF3F0dSNI1gtEi6O0DusC6OkA+kStocebvib9
            9VLqCJ7tTDmJGJBQqBIICVTFJrnUOLBrxrW6wYg8t4bieeaWo6aCDgMORyXYEi6s
            8QYAVt6ELDmfY3tIK4pQxx2EWOUDAeczIFqx0PtA4csnFOU84OT6DAYZBrcrtahB
            snW9n2wx1EzvMrnYhuDJPY7dwMJIH1jFIAZLMwIDAQABo4ID0zCCA88wDAYDVR0T
            AQH/BAIwADAfBgNVHSMEGDAWgBTTvcE8oM81uTTF1NvaEA5M3mr+WDB6BggrBgEF
            BQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jZXJ0cy5hcHBsZS5jb20vYXBl
            dnNyc2ExZzEuZGVyMDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBsZS5jb20v
            b2NzcDAzLWFwZXZzcnNhMWcxMDEwPAYDVR0RBDUwM4IQaW1hZ2VzLmFwcGxlLmNv
            bYINd3d3LmFwcGxlLmNvbYIQd3d3LmFwcGxlLmNvbS5jbjBgBgNVHSAEWTBXMEgG
            BWeBDAEBMD8wPQYIKwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0
            aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMwCwYJYIZIAYb9bAIBMBMGA1UdJQQMMAoG
            CCsGAQUFBwMBMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29t
            L2FwZXZzcnNhMWcxLmNybDAdBgNVHQ4EFgQUsYvlS10MqKLYBaxFqMlTrsUPubAw
            DgYDVR0PAQH/BAQDAgWgMA8GCSqGSIb3Y2QGVgQCBQAwggH0BgorBgEEAdZ5AgQC
            BIIB5ASCAeAB3gB1AJROQ4f67MHvgfMZJCaoGGUBx9NfOAIBP3JnfVU3LhnYAAAB
            nE3W1lgAAAQDAEYwRAIgVZYmJmSrX0I48qD3ga9siB4X+ABlwS46NibY7CGB67oC
            IBAQ/tzmhDmJTsQPVsxyB8zzNCFILG3x9KXi84xFDSn/AHYAyKPEf8ezrbk1awE/
            anoSbeM6TkOlxkb5l605dZkdz5oAAAGcTdbWbAAABAMARzBFAiEAp40+gQNimcjv
            5nEpubXnCj+XFNybUatiM0sLr+dXiswCIB+nWWZdG8YT3lLXGMjCOz9+wYEpwnDO
            m484HO6ExgRlAHYA1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXcAAAGc
            TdbWWgAABAMARzBFAiAIC0mUpuft8PG9ro6a3cIre4WawkbDvWNddyCEfow9gQIh
            AJeHkOZPRSpME/Q8XDSa7hIOYl/0sffaXthwn0MnZaqqAHUAwjF+V0UZo0Xufzje
            spBB68fCIVoiv3/Vta12mtkOUs0AAAGcTdbWdwAABAMARjBEAiBjs2ij+9e0NCA7
            +aUagaghDIaRm2ebKL2Oq8IHTfXrLQIgJ1LUZZI0r+DEnWN84L+kYfDE2bHKLiAq
            oRlB4aVdxMwwDQYJKoZIhvcNAQELBQADggEBAIYpW3UNZnJJGsYhOZ+CFutCLPGS
            MbKPr8nIHXlh4tP3cxkE1D8SUDzsp+81DwzhkJ8cFPz2JlxzFTWMlumo/vWFxO54
            OLp0gAbEYBjOFuzf8A32XSwSo6Xoj+dpvD24gje8+COxNaAWsbUQdm9E0oRWsMd9
            ZcORi6J1Tywhb1uqvMa1XDhtZXEG/yzwtbDQbBHYNBgXPG5odSCzuqfL2aZIcorR
            zfsZ3Q+cvy/SSsHSFKqXiZHRVuF86IxxcYtnzzppYFBi5ZfvWyyRlXvK2mGWfkjj
            H+oCFWiClVTllg31d5XLuWTSY1gc8KqbHsGIjKv9FxqHQxokzIjMlyB+T68=
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
