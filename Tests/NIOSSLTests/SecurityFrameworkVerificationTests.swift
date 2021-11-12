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
#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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
        #if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
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

#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
extension SecurityFrameworkVerificationTests {
    static let appleComCertChain: [SecCertificate] = {
        // All certs here are PEM format, with the leading/trailing lines stripped.
        let leaf = """
            MIIGlTCCBjugAwIBAgIQXpZhw91DyrfQnSTEKafHCDAKBggqhkjOPQQDAjBRMQsw
            CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBwbGUg
            UHVibGljIEVWIFNlcnZlciBFQ0MgQ0EgMSAtIEcxMB4XDTIxMDYyMjExMjYzNloX
            DTIyMDcyMjExMjYzNVowgeoxHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9u
            MRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQITCkNhbGlmb3Ju
            aWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs
            aWZvcm5pYTESMBAGA1UEBxMJQ3VwZXJ0aW5vMRMwEQYDVQQKEwpBcHBsZSBJbmMu
            MSUwIwYDVQQLExxtYW5hZ2VtZW50OmlkbXMuZ3JvdXAuNjY1MDM1MRIwEAYDVQQD
            EwlhcHBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT/I3EwP3KxsPqd
            HALz1EQSrupxwJw//JX1d6+Cro2ING7SVWFi6UeXbvLkAC72p9iWAqwhqrv3Kn+0
            DDfLezZIo4IEWTCCBFUwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTghUh9E6bT
            EBmfXMtreCSS+K4brjB6BggrBgEFBQcBAQRuMGwwMgYIKwYBBQUHMAKGJmh0dHA6
            Ly9jZXJ0cy5hcHBsZS5jb20vYXBldnNlY2MxZzEuZGVyMDYGCCsGAQUFBzABhipo
            dHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwZXZzZWNjMWcxMDEwFAYDVR0R
            BA0wC4IJYXBwbGUuY29tMIIBEgYDVR0gBIIBCTCCAQUwBwYFZ4EMAQEwgfkGCWCG
            SAGG/WwCATCB6zA+BggrBgEFBQcCARYyaHR0cHM6Ly93d3cuYXBwbGUuY29tL2Nl
            cnRpZmljYXRlYXV0aG9yaXR5L3B1YmxpYy8wgagGCCsGAQUFBwICMIGbDIGYUmVs
            aWFuY2Ugb24gdGhpcyBjZXJ0aWZpY2F0ZSBieSBhbnkgcGFydHkgYXNzdW1lcyBh
            Y2NlcHRhbmNlIG9mIHRoZSBSZWx5aW5nIFBhcnR5IEFncmVlbWVudCBmb3VuZCBh
            dCBodHRwczovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvcHVi
            bGljLy4wHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMDUGA1UdHwQuMCww
            KqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwZXZzZWNjMWcxLmNybDAdBgNV
            HQ4EFgQUNXvIortNr4uX98t9ZMoYXPzCcKwwDgYDVR0PAQH/BAQDAgOIMIIB9QYK
            KwYBBAHWeQIEAgSCAeUEggHhAd8AdgCkuQmQtBhYFIe7E6LMZ3AKPDWYBPkb37jj
            d80OyA3cEAAAAXozggXBAAAEAwBHMEUCIQC91Po5I/bqD4UdWrY1pdZ7I4d0znH7
            CZPhczPT4lms/wIgICyG1UEA/fGEfL8q2YGT4vKNWPNLGN7j/ax34jDBaJIAdgBW
            FAaaL9fC7NP14b1Esj7HRna5vJkRXMDvlJhV1onQ3QAAAXozggXAAAAEAwBHMEUC
            IQDfqscO4LFLK+X+OJkyjighJLaz61ED3J2ktZhe/TGXxgIgQRAsjeELRBbUj1x1
            lJ+TJxTSGv1bFAWn+ImUe68AmT8AdQBRo7D1/QF5nFZtuDd4jwykeswbJ8v3nohC
            mg3+1IsF5QAAAXozggXcAAAEAwBGMEQCIDUPVXArZ1aTWEm7Wk5N6T6YD8f1P48u
            JWY5tq3vh4oEAiBvkgimSx7QKokNIwjW7oa8iEpCJEM3Y/CP52OBnUyUYgB2AEal
            Vet1+pEgMLWiiWn0830RLEF0vv1JuIWr8vxw/m1HAAABejOCBeYAAAQDAEcwRQIg
            dfWT0/px9bVlgxU7GQFmpnQCZJyLiyspfB7KvfobZD8CIQDCf1yZvoDcypXdESvO
            1S6eChrc1CeQoWtIHWJ2JGSFdzAKBggqhkjOPQQDAgNIADBFAiAvKPVZREcRx2t2
            Y2L4z2HZg92B8tPZ2Cr13vApu75JJgIhAO1OsrKmMNLOQcfhU8gFyS47kEH08hX2
            5xdUw2zK9i8b
            """

        let intermediate = """
            MIIDsjCCAzigAwIBAgIQDKuq0c7E6XzCZliB0CE49zAKBggqhkjOPQQDAzBhMQsw
            CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
            ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
            Fw0yMDA0MjkxMjM0NTJaFw0zMDA0MTAyMzU5NTlaMFExCzAJBgNVBAYTAlVTMRMw
            EQYDVQQKEwpBcHBsZSBJbmMuMS0wKwYDVQQDEyRBcHBsZSBQdWJsaWMgRVYgU2Vy
            dmVyIEVDQyBDQSAxIC0gRzEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQp+OFa
            uYdEBJj/FpCG+eDhQmVfhv0DGPzGz40TW8BeWxipYTOa4FLieAYoU+3t2tg9FZKt
            A4BDTO43YprLZm6zo4IB4DCCAdwwHQYDVR0OBBYEFOCFSH0TptMQGZ9cy2t4JJL4
            rhuuMB8GA1UdIwQYMBaAFLPbSKT5ocXYrjZBzBFjaWIpvEvGMA4GA1UdDwEB/wQE
            AwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgw
            BgEB/wIBADA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
            LmRpZ2ljZXJ0LmNvbTBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdp
            Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290RzMuY3JsMIHcBgNVHSAEgdQwgdEw
            gcUGCWCGSAGG/WwCATCBtzAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl
            cnQuY29tL0NQUzCBigYIKwYBBQUHAgIwfgx8QW55IHVzZSBvZiB0aGlzIENlcnRp
            ZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcgUGFy
            dHkgQWdyZWVtZW50IGxvY2F0ZWQgYXQgaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t
            L3JwYS11YTAHBgVngQwBATAKBggqhkjOPQQDAwNoADBlAjEAyHLAT/4iBuxi4/NH
            hZde4PZO8CnG2/A3oGO0Nsjpoe2SV94Hr+JpYHrBzT8hyeKSAjBnRXyRac9sM8KN
            Fdg3+7LWIiW9sUjtJC6kGmRyGm6vV4oAhEDd9jdk4q+7b5zlid4=
            """

        // We shouldn't really need the root, but at the time of writing apple.com
        // served it so we will too.
        let root = """
            MIICPzCCAcWgAwIBAgIQBVVWvPJepDU1w6QP1atFcjAKBggqhkjOPQQDAzBhMQsw
            CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
            ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
            Fw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUw
            EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
            IDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMHYwEAYHKoZIzj0CAQYF
            K4EEACIDYgAE3afZu4q4C/sLfyHS8L6+c/MzXRq8NOrexpu80JX28MzQC7phW1FG
            fp4tn+6OYwwX7Adw9c+ELkCDnOg/QW07rdOkFFk2eJ0DQ+4QE2xy3q6Ip6FrtUPO
            Z9wj/wMco+I+o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAd
            BgNVHQ4EFgQUs9tIpPmhxdiuNkHMEWNpYim8S8YwCgYIKoZIzj0EAwMDaAAwZQIx
            AK288mw/EkrRLTnDCgmXc/SINoyIJ7vmiI1Qhadj+Z4y3maTD/HMsQmP3Wyr+mt/
            oAIwOWZbwmSNuJ5Q3KjVSaLtx9zRSX8XAbjIho9OjIgrqJqpisXRAL34VOKa5Vt8
            sycX
            """

        return [leaf, intermediate, root].map {
            SecCertificateCreateWithData(nil, Data(base64Encoded: $0, options: .ignoreUnknownCharacters)! as CFData)!
        }
    }()
}
#endif
