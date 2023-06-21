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
    static let appleComCertChain: [SecCertificate] = {
        // All certs here are PEM format, with the leading/trailing lines stripped.
        let leaf = """
            MIIGdDCCBhqgAwIBAgIQZ2Hv/Zg3XNIdroj6PdpXdjAKBggqhkjOPQQDAjBRMQsw
            CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEtMCsGA1UEAxMkQXBwbGUg
            UHVibGljIEVWIFNlcnZlciBFQ0MgQ0EgMSAtIEcxMB4XDTIzMDUwMjIzMDMzNloX
            DTIzMTAyOTIzMTMzNlowgcoxGTAXBgNVBAMTEGltYWdlcy5hcHBsZS5jb20xEzAR
            BgNVBAoTCkFwcGxlIEluYy4xEjAQBgNVBAcTCUN1cGVydGlubzETMBEGA1UECBMK
            Q2FsaWZvcm5pYTELMAkGA1UEBhMCVVMxETAPBgNVBAUTCEMwODA2NTkyMRswGQYL
            KwYBBAGCNzwCAQITCkNhbGlmb3JuaWExEzARBgsrBgEEAYI3PAIBAxMCVVMxHTAb
            BgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0D
            AQcDQgAESGCOCKkGXa5kh9FiauXGtuMmiAVhX3CKPtSBNHKJJIdd4HN63m4ToJbE
            PRoXUt08BZ4N4ttCTML51Aw1aBapDaOCBFgwggRUMAwGA1UdEwEB/wQCMAAwHwYD
            VR0jBBgwFoAU4IVIfROm0xAZn1zLa3gkkviuG64wegYIKwYBBQUHAQEEbjBsMDIG
            CCsGAQUFBzAChiZodHRwOi8vY2VydHMuYXBwbGUuY29tL2FwZXZzZWNjMWcxLmRl
            cjA2BggrBgEFBQcwAYYqaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcGV2
            c2VjYzFnMTAxMBsGA1UdEQQUMBKCEGltYWdlcy5hcHBsZS5jb20wggESBgNVHSAE
            ggEJMIIBBTAHBgVngQwBATCB+QYJYIZIAYb9bAIBMIHrMD4GCCsGAQUFBwIBFjJo
            dHRwczovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkvcHVibGlj
            LzCBqAYIKwYBBQUHAgIwgZsMgZhSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRl
            IGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcg
            UGFydHkgQWdyZWVtZW50IGZvdW5kIGF0IGh0dHBzOi8vd3d3LmFwcGxlLmNvbS9j
            ZXJ0aWZpY2F0ZWF1dGhvcml0eS9wdWJsaWMvLjATBgNVHSUEDDAKBggrBgEFBQcD
            ATA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLmFwcGxlLmNvbS9hcGV2c2Vj
            YzFnMS5jcmwwHQYDVR0OBBYEFJJ7SA684vmEsFuyOKe4StG62unlMA4GA1UdDwEB
            /wQEAwIHgDCCAfcGCisGAQQB1nkCBAIEggHnBIIB4wHhAHYAs3N3B+GEUPhjhtYF
            qdwRCUp5LbFnDAuH3PADDnk2pZoAAAGH3r4ohwAABAMARzBFAiEAug08j7lk0wkU
            aRfSKEx9gQ6JptHvjXOsEicMjnYDmV0CIBSRHT6uRTJmW1Sh8oZIUUtFOqfRcET1
            rzHY5b/36UDXAHUA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAGH
            3r4obgAABAMARjBEAiBUad4NuoD88Myr+iuXdxP+iBOzx/MKol0q9ecUJIPCkwIg
            QVyxYVKAMg7nMn97SUpJXblBgucqPmhwFbEup6sYZZUAdwB6MoxU2LcttiDqOOBS
            HumEFnAyE4VNO9IrwTpXo1LrUgAAAYfeviiHAAAEAwBIMEYCIQDM7+zlZMV3jKJp
            tBMvfjjNLaF4B5CDPjT64/MX8EOzegIhAKgr0qGT4YmBYAY+rWX/KaeO0YaZnaGS
            328e2VLhRi2UAHcAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGH
            3r4oiQAABAMASDBGAiEAshggN7MlSpMJUSSa9Epx3dtHv94JdAolfCHnPrHRw5EC
            IQCZCBotNyYvzFpVXZVMjIWJG7WBrUeczvEB+FoLBEWuVzAKBggqhkjOPQQDAgNI
            ADBFAiEAwboT1owMpJ+QI8Xqw0QK5q5bedNid+kTgiBdb9f6F6wCIF//9mVdazz+
            yg1qIrFTtejnZCdffuE6G44UpP9A6/2F
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
