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

import NIOCore
import XCTest

@testable import NIOSSL

/// This cert contains the following SAN fields:
/// DNS:*.WILDCARD.EXAMPLE.com - A straightforward wildcard, should be accepted
/// DNS:FO*.EXAMPLE.com - A suffix wildcard, should be accepted
/// DNS:*AR.EXAMPLE.com - A prefix wildcard, should be accepted
/// DNS:B*Z.EXAMPLE.com - An infix wildcard
/// DNS:TRAILING.PERIOD.EXAMPLE.com. - A domain with a trailing period, should match
/// DNS:XN--STRAE-OQA.UNICODE.EXAMPLE.com. - An IDN A-label, should match.
/// DNS:XN--X*-GIA.UNICODE.EXAMPLE.com. - An IDN A-label with a wildcard, invalid.
/// DNS:WEIRDWILDCARD.*.EXAMPLE.com. - A wildcard not in the leftmost label, invalid.
/// DNS:*.*.DOUBLE.EXAMPLE.com. - Two wildcards, invalid.
/// DNS:*.XN--STRAE-OQA.EXAMPLE.com. - A wildcard followed by a new IDN A-label, this is fine.
/// A SAN with a null in it, should be ignored.
///
/// This also contains a commonName of httpbin.org.
private let weirdoPEMCert = """
    -----BEGIN CERTIFICATE-----
    MIICZjCCAgygAwIBAgIURNa5MCGhhy1TUo57ogfm5OvVBr8wCgYIKoZIzj0EAwIw
    FjEUMBIGA1UEAwwLaHR0cGJpbi5vcmcwHhcNMjQwNTEzMTI1MjUwWhcNNDAwMTAx
    MDAwMDAwWjAWMRQwEgYDVQQDDAtodHRwYmluLm9yZzBZMBMGByqGSM49AgEGCCqG
    SM49AwEHA0IABHC44jasAWsWYtYdo+cnLOAEuMQHt1zI5A7td2avNIHEfEXqiizj
    t1VPWYR6wbL/X7ZXb7IjED8v5ZeN/yK0jpGjggE2MIIBMjAJBgNVHRMEAjAAMIIB
    IwYDVR0RBIIBGjCCARaCFiouV0lMRENBUkQuRVhBTVBMRS5jb22CD0ZPKi5FWEFN
    UExFLmNvbYIPKkFSLkVYQU1QTEUuY29tgg9CKlouRVhBTVBMRS5jb22CHFRSQUlM
    SU5HLlBFUklPRC5FWEFNUExFLmNvbS6CIlhOLS1TVFJBRS1PUUEuVU5JQ09ERS5F
    WEFNUExFLmNvbS6CH1hOLS1YKi1HSUEuVU5JQ09ERS5FWEFNUExFLmNvbS6CHFdF
    SVJEV0lMRENBUkQuKi5FWEFNUExFLmNvbS6CFyouKi5ET1VCTEUuRVhBTVBMRS5j
    b20ughwqLlhOLS1TVFJBRS1PUUEuRVhBTVBMRS5jb20ughFOVUwATC5FWEFNUExF
    LmNvbTAKBggqhkjOPQQDAgNIADBFAiEAoZP9/AT/kI4XV9ComU/3TOBavn2HT4KJ
    GLTqsl138zwCIFAGdxsBH3CGfuFNYXOdYZOJ/FIqv7Ev0eGxXvTZ+bcs
    -----END CERTIFICATE-----
    """

/// Returns whether this system supports resolving IPv6 function.
func ipv6Supported() throws -> Bool {
    do {
        _ = try SocketAddress.makeAddressResolvingHost("2001:db8::1", port: 443)
        return true
    } catch SocketAddressError.unknown {
        return false
    }
}

class IdentityVerificationTest: XCTestCase {
    func testCanValidateHostnameInFirstSan() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "localhost",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testCanValidateHostnameInSecondSan() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testIgnoresTrailingPeriod() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "example.com.",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testLowercasesHostnameForSan() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "LoCaLhOsT",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testRejectsIncorrectHostname() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "httpbin.org",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testAcceptsIpv4Address() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: nil,
            socketAddress: try .init(ipAddress: "192.168.0.1", port: 443),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testAcceptsIpv6Address() throws {
        guard try ipv6Supported() else { return }
        let ipv6Address = try SocketAddress(ipAddress: "2001:db8::1", port: 443)

        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: nil,
            socketAddress: ipv6Address,
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testRejectsIncorrectIpv4Address() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: nil,
            socketAddress: try .init(ipAddress: "192.168.0.2", port: 443),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testRejectsIncorrectIpv6Address() throws {
        guard try ipv6Supported() else { return }
        let ipv6Address = try SocketAddress(ipAddress: "2001:db8::2", port: 443)

        let cert = try NIOSSLCertificate(bytes: .init(multiSanCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: nil,
            socketAddress: ipv6Address,
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testAcceptsWildcards() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "this.wildcard.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testAcceptsSuffixWildcard() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "foo.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testAcceptsPrefixWildcard() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "bar.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testAcceptsInfixWildcard() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "baz.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testIgnoresTrailingPeriodInCert() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "trailing.period.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testRejectsEncodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)

        XCTAssertThrowsError(
            try validIdentityForService(
                serverHostname: "straße.unicode.example.com",
                socketAddress: try .init(unixDomainSocketPath: "/path"),
                leafCertificate: cert
            )
        ) { error in
            XCTAssertEqual(error as? NIOSSLExtraError, .serverHostnameImpossibleToMatch)
            XCTAssertEqual(
                String(describing: error),
                "NIOSSLExtraError.serverHostnameImpossibleToMatch: The server hostname straße.unicode.example.com cannot be matched due to containing non-DNS characters"
            )
        }

    }

    func testMatchesUnencodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "xn--strae-oqa.unicode.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testDoesNotMatchIDNALabelWithWildcard() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "xn--xx-gia.unicode.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testDoesNotMatchNonLeftmostWildcards() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "weirdwildcard.nomatch.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testDoesNotMatchMultipleWildcards() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "one.two.double.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testRejectsWildcardBeforeUnencodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)

        XCTAssertThrowsError(
            try validIdentityForService(
                serverHostname: "foo.straße.example.com",
                socketAddress: try .init(unixDomainSocketPath: "/path"),
                leafCertificate: cert
            )
        ) { error in
            XCTAssertEqual(error as? NIOSSLExtraError, .serverHostnameImpossibleToMatch)
            XCTAssertEqual(
                String(describing: error),
                "NIOSSLExtraError.serverHostnameImpossibleToMatch: The server hostname foo.straße.example.com cannot be matched due to containing non-DNS characters"
            )
        }
    }

    func testMatchesWildcardBeforeEncodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "foo.xn--strae-oqa.example.com",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testDoesNotMatchSANWithEmbeddedNULL() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)

        XCTAssertThrowsError(
            try validIdentityForService(
                serverHostname: "nul\u{0000}l.example.com",
                socketAddress: try .init(unixDomainSocketPath: "/path"),
                leafCertificate: cert
            )
        ) { error in
            XCTAssertEqual(error as? NIOSSLExtraError, .serverHostnameImpossibleToMatch)
            XCTAssertEqual(
                String(describing: error),
                "NIOSSLExtraError.serverHostnameImpossibleToMatch: The server hostname nul\u{0000}l.example.com cannot be matched due to containing non-DNS characters"
            )
        }
    }

    func testFallsBackToCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiCNCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "localhost",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testLowercasesForCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(multiCNCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "LoCaLhOsT",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertTrue(matched)
    }

    func testRejectsUnicodeCommonNameWithUnencodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(unicodeCNCert.utf8), format: .pem)

        XCTAssertThrowsError(
            try validIdentityForService(
                serverHostname: "straße.org",
                socketAddress: try .init(unixDomainSocketPath: "/path"),
                leafCertificate: cert
            )
        ) { error in
            XCTAssertEqual(error as? NIOSSLExtraError, .serverHostnameImpossibleToMatch)
            XCTAssertEqual(
                String(describing: error),
                "NIOSSLExtraError.serverHostnameImpossibleToMatch: The server hostname straße.org cannot be matched due to containing non-DNS characters"
            )
        }
    }

    func testRejectsUnicodeCommonNameWithEncodedIDNALabel() throws {
        let cert = try NIOSSLCertificate(bytes: .init(unicodeCNCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "xn--strae-oqa.org",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testHandlesMissingCommonName() throws {
        let cert = try NIOSSLCertificate(bytes: .init(noCNCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "localhost",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }

    func testDoesNotFallBackToCNWithSans() throws {
        let cert = try NIOSSLCertificate(bytes: .init(weirdoPEMCert.utf8), format: .pem)
        let matched = try validIdentityForService(
            serverHostname: "httpbin.org",
            socketAddress: try .init(unixDomainSocketPath: "/path"),
            leafCertificate: cert
        )
        XCTAssertFalse(matched)
    }
}
