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
            MIIGpjCCBkugAwIBAgIQKJx5JD51vHmvWQd4OD7NzDAKBggqhkjOPQQDAjBRMQsw
            CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBwbGUg
            UHVibGljIEVWIFNlcnZlciBFQ0MgQ0EgMSAtIEcxMB4XDTIyMDQxOTE2MDUxNFoX
            DTIzMDUxOTE2MDUxM1owgfExHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9u
            MRMwEQYLKwYBBAGCNzwCAQMTAlVTMRswGQYLKwYBBAGCNzwCAQITCkNhbGlmb3Ju
            aWExETAPBgNVBAUTCEMwODA2NTkyMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs
            aWZvcm5pYTESMBAGA1UEBxMJQ3VwZXJ0aW5vMRMwEQYDVQQKEwpBcHBsZSBJbmMu
            MSUwIwYDVQQLExxtYW5hZ2VtZW50OmlkbXMuZ3JvdXAuNjY1MDM1MRkwFwYDVQQD
            ExBpbWFnZXMuYXBwbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEipqG
            cwwgDSIc04hxl4uQTMnkOCDWzr8VfcYiAFqKMiA6Y1cuSnPjoZI7CALLDjZJMD3k
            fUsPBG7wHmvNRHzAoKOCBGIwggReMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAU
            4IVIfROm0xAZn1zLa3gkkviuG64wegYIKwYBBQUHAQEEbjBsMDIGCCsGAQUFBzAC
            hiZodHRwOi8vY2VydHMuYXBwbGUuY29tL2FwZXZzZWNjMWcxLmRlcjA2BggrBgEF
            BQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcGV2c2VjYzFnMTAx
            MBsGA1UdEQQUMBKCEGltYWdlcy5hcHBsZS5jb20wggESBgNVHSAEggEJMIIBBTAH
            BgVngQwBATCB+QYJYIZIAYb9bAIBMIHrMD4GCCsGAQUFBwIBFjJodHRwczovL3d3
            dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvcHVibGljLzCBqAYIKwYB
            BQUHAgIwgZsMgZhSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBw
            YXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcgUGFydHkgQWdy
            ZWVtZW50IGZvdW5kIGF0IGh0dHBzOi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0
            ZWF1dGhvcml0eS9wdWJsaWMvLjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
            AwEwNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5hcHBsZS5jb20vYXBldnNl
            Y2MxZzEuY3JsMB0GA1UdDgQWBBQeaqBRkKzrOYrGlikf46YzaU5WpDAOBgNVHQ8B
            Af8EBAMCB4AwggH3BgorBgEEAdZ5AgQCBIIB5wSCAeMB4QB2ALvZ37wfinG1k5Qj
            l6qSe0c4V5UKq1LoGpCWZDaOHtGFAAABgEKbSRUAAAQDAEcwRQIhAI1x8dlzc4sI
            +tekm5BTwmymwxZcg0AIqgXqgXBSRkyWAiAqC4/OqLssOjzQc3PAF+vnaydgda1M
            Ogt+sF9d2lCn/QB3AKS5CZC0GFgUh7sTosxncAo8NZgE+RvfuON3zQ7IDdwQAAAB
            gEKbSRYAAAQDAEgwRgIhAIPUQ4CH6jhWcTrnmjbOw4N+iRwm10LkpsA/SnuAdUtN
            AiEA7kVKU413xOctBAYcgpj5WZRXJ4HE5MG5/Gg+j6YZoiEAdgB6MoxU2LcttiDq
            OOBSHumEFnAyE4VNO9IrwTpXo1LrUgAAAYBCm0lRAAAEAwBHMEUCIFNKhLMB3i6k
            NfHrfoN+dhRoZZrh+FSwscHvnYbC3phAAiEAvoneV6lqyKicUd7/zArHOns6IXZd
            l4sQIEkbsCVf6AIAdgCt9776fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAA
            AYBCm0k7AAAEAwBHMEUCIE3TT2/uhFmrgfprb0hewqsCRw7RT7kVUhVwT/E11o8l
            AiEA3kgU/SGMqu+74BHllW1+P2ZcePAuefqxEFNvFlgkVAgwCgYIKoZIzj0EAwID
            SQAwRgIhAK1YRIj06iciVrN8yJWO0JTB+/d/XJDXDX8eGu0io3StAiEAoqyVS1Tm
            A9qxgk2DsibWyckLQn5CAk+ypmA/zQ4H79M=
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
