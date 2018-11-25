//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CNIOOpenSSL

/// Known and supported TLS versions.
public enum TLSVersion {
    case sslv2
    case sslv3
    case tlsv1
    case tlsv11
    case tlsv12
    case tlsv13
}

/// Places OpenSSL can obtain certificates from.
public enum OpenSSLCertificateSource {
    case file(String)
    case certificate(OpenSSLCertificate)
}

/// Places OpenSSL can obtain private keys from.
public enum OpenSSLPrivateKeySource {
    case file(String)
    case privateKey(OpenSSLPrivateKey)
}

/// Places OpenSSL can obtain a trust store from.
public enum OpenSSLTrustRoots {
    case file(String)
    case certificates([OpenSSLCertificate])
    case `default`
}

/// Formats OpenSSL supports for serializing keys and certificates.
public enum OpenSSLSerializationFormats {
    case pem
    case der
}

/// Certificate verification modes.
public enum CertificateVerification {
    /// All certificate verification disabled.
    case none

    /// Certificates will be validated against the trust store, but will not
    /// be checked to see if they are valid for the given hostname.
    case noHostnameVerification

    /// Certificates will be validated against the trust store and checked
    /// against the hostname of the service we are contacting.
    case fullVerification
}

/// A secure default configuration of cipher suites for TLS 1.2 and earlier.
///
/// The goal of this cipher suite string is:
/// - Prefer cipher suites that offer Perfect Forward Secrecy (DHE/ECDHE)
/// - Prefer ECDH(E) to DH(E) for performance.
/// - Prefer any AEAD cipher suite over non-AEAD suites for better performance and security
/// - Prefer AES-GCM over ChaCha20 because hardware-accelerated AES is common
/// - Disable NULL authentication and encryption and any appearance of MD5
public let defaultCipherSuites = [
    "ECDH+AESGCM",
    "ECDH+CHACHA20",
    "DH+AESGCM",
    "DH+CHACHA20",
    "ECDH+AES256",
    "DH+AES256",
    "ECDH+AES128",
    "DH+AES",
    "RSA+AESGCM",
    "RSA+AES",
    "!aNULL",
    "!eNULL",
    "!MD5",
    ].joined(separator: ":")


/// A secure default configuration of cipher suites for TLS 1.3 and later.
///
/// There are currently very few bad choices for TLS 1.3, so this string does the
/// following:
/// - Disable CCM mode because there's no reason to enable it, and cipher suites
///   aren't collectibles.
/// - Prefer AES-GCM over ChaCha20 because hardware-accelerated AES is common.
public let defaultTLS13CipherSuites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    ].joined(separator: ":")

/// Encodes a string to the wire format of an ALPN identifier. These MUST be ASCII, and so
/// this routine will crash the program if they aren't, as these are always user-supplied
/// strings.
internal func encodeALPNIdentifier(identifier: String) -> [UInt8] {
    var encodedIdentifier = [UInt8]()
    encodedIdentifier.append(UInt8(identifier.utf8.count))

    for codePoint in identifier.unicodeScalars {
        encodedIdentifier.append(contentsOf: Unicode.ASCII.encode(codePoint)!)
    }

    return encodedIdentifier
}

/// Manages configuration of OpenSSL for SwiftNIO programs.
///
/// OpenSSL has a number of configuration options that are worth setting. This structure allows
/// setting those options in a more expressive manner than OpenSSL itself allows.
public struct TLSConfiguration {
    /// A default TLS configuration for client use.
    public static let clientDefault = TLSConfiguration.forClient()

    /// The minimum TLS version to allow in negotiation. Defaults to tlsv1.
    public var minimumTLSVersion: TLSVersion

    /// The maximum TLS version to allow in negotiation. If nil, there is no upper limit. Defaults to nil.
    public var maximumTLSVersion: TLSVersion?

    /// The pre-TLS1.3 cipher suites supported by this handler. This uses the OpenSSL cipher string format.
    /// To introspect the TLS 1.3 cipher suites, use tls13CipherSuites.
    public var cipherSuites: String

    /// The TLS 1.3 and later cipher suites supported by this handler, using the OpenSSL cipher string
    /// format.
    ///
    /// These are separate from the pre-TLS1.3 cipher suites because they are configured very differently
    /// in OpenSSL, and are quite different from their earlier cousins with the same name. In particular,
    /// TLS 1.3 cipher suites do not specify the certificate type (e.g. RSA/ECDSA) or key exchange
    /// mechanism (e.g. RSA/ECDHE).
    public var tls13CipherSuites: String

    /// Whether to verify remote certificates.
    public var certificateVerification: CertificateVerification

    /// The trust roots to use to validate certificates. This only needs to be provided if you intend to validate
    /// certificates.
    public var trustRoots: OpenSSLTrustRoots?

    /// The certificates to offer during negotiation. If not present, no certificates will be offered.
    public var certificateChain: [OpenSSLCertificateSource]

    /// The private key associated with the leaf certificate.
    public var privateKey: OpenSSLPrivateKeySource?

    /// The application protocols to use in the connection. Should be an ordered list of ASCII
    /// strings representing the ALPN identifiers of the protocols to negotiate. For clients,
    /// the protocols will be offered in the order given. For servers, the protocols will be matched
    /// against the client's offered protocols in order.
    public var applicationProtocols: [[UInt8]]

    private init(cipherSuites: String,
                 tls13CipherSuites: String,
                 minimumTLSVersion: TLSVersion,
                 maximumTLSVersion: TLSVersion?,
                 certificateVerification: CertificateVerification,
                 trustRoots: OpenSSLTrustRoots,
                 certificateChain: [OpenSSLCertificateSource],
                 privateKey: OpenSSLPrivateKeySource?,
                 applicationProtocols: [String]) {
        self.cipherSuites = cipherSuites
        self.tls13CipherSuites = tls13CipherSuites
        self.minimumTLSVersion = minimumTLSVersion
        self.maximumTLSVersion = maximumTLSVersion
        self.certificateVerification = certificateVerification
        self.trustRoots = trustRoots
        self.certificateChain = certificateChain
        self.privateKey = privateKey
        self.applicationProtocols = applicationProtocols.map(encodeALPNIdentifier)
    }

    /// Create a TLS configuration for use with server-side contexts.
    ///
    /// This provides sensible defaults while requiring that you provide any data that is necessary
    /// for server-side function. For client use, try `forClient` instead.
    public static func forServer(certificateChain: [OpenSSLCertificateSource],
                                 privateKey: OpenSSLPrivateKeySource,
                                 cipherSuites: String = defaultCipherSuites,
                                 tls13CipherSuites: String = defaultTLS13CipherSuites,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .none,
                                 trustRoots: OpenSSLTrustRoots = .default,
                                 applicationProtocols: [String] = []) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                tls13CipherSuites: tls13CipherSuites,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols)
    }


    /// Creates a TLS configuration for use with client-side contexts.
    ///
    /// This provides sensible defaults, and can be used without customisation. For server-side
    /// contexts, you should use `forServer` instead.
    public static func forClient(cipherSuites: String = defaultCipherSuites,
                                 tls13CipherSuites: String = defaultTLS13CipherSuites,
                                 minimumTLSVersion: TLSVersion = .tlsv1,
                                 maximumTLSVersion: TLSVersion? = nil,
                                 certificateVerification: CertificateVerification = .fullVerification,
                                 trustRoots: OpenSSLTrustRoots = .default,
                                 certificateChain: [OpenSSLCertificateSource] = [],
                                 privateKey: OpenSSLPrivateKeySource? = nil,
                                 applicationProtocols: [String] = []) -> TLSConfiguration {
        return TLSConfiguration(cipherSuites: cipherSuites,
                                tls13CipherSuites: tls13CipherSuites,
                                minimumTLSVersion: minimumTLSVersion,
                                maximumTLSVersion: maximumTLSVersion,
                                certificateVerification: certificateVerification,
                                trustRoots: trustRoots,
                                certificateChain: certificateChain,
                                privateKey: privateKey,
                                applicationProtocols: applicationProtocols)
    }
}
