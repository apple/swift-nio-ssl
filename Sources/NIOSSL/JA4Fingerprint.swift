//
//  File.swift
//  
//
//  Created by Andrew Barba on 7/23/24.
//

@_implementationOnly import CNIOBoringSSL

public struct JA4Fingerprint {
    // JA4_a
    var networkProtocol: String
    var tlsVersion: Int32
    var sni: String
    var numberOfCipherSuites: Int
    var numberOfExtensions: Int
    var firstALPN: String

    // JA4_b
    var cipherSuites: [UInt16]

    // JA4_c
    var extensions: [UInt16]
    var signatureAlgorithms: [UInt16]

    init(clientExtensionValues: NIOSSLClientExtensionValues, networkProtocol: String) {
        self.networkProtocol = networkProtocol
        self.tlsVersion = clientExtensionValues.tlsVersion ?? 0
        self.sni = clientExtensionValues.serverHostname != nil ? "d" : "i"
        self.numberOfCipherSuites = clientExtensionValues.cipherSuites?.filter { !isGREASEUint16($0) }.count ?? 0
        self.numberOfExtensions = clientExtensionValues.extensions?.filter { !isGREASEUint16($0) }.count ?? 0
        self.firstALPN = clientExtensionValues.alpnProtocols?.first.map { String($0.prefix(1) + $0.suffix(1)) } ?? "00"
        self.cipherSuites = clientExtensionValues.cipherSuites?.filter { !isGREASEUint16($0) }.sorted() ?? []
        self.extensions = clientExtensionValues.extensions?.filter { !isGREASEUint16($0) }.sorted() ?? []
        self.signatureAlgorithms = clientExtensionValues.signatureAlgorithms ?? []
    }

    public func digest() -> String {
        let tls = tlsVersionString(tlsVersion: self.tlsVersion)

        let ja4a = String(format: "%@%@%@%02d%02d%@",
                          self.networkProtocol,
                          tls,
                          self.sni,
                          self.numberOfCipherSuites,
                          self.numberOfExtensions,
                          self.firstALPN)

        let ja4b = truncatedSha256Hex(cipherSuites.map { String(format: "%04x", $0) }.joined(separator: ","))

        let extensionsString = extensions
            .map { String(format: "%04x", $0) }
            .joined(separator: ",")

        let signatureAlgorithmsString = signatureAlgorithms
            .map { String(format: "%04x", $0) }
            .joined(separator: ",")

        let ja4c: String
        if signatureAlgorithms.isEmpty {
            ja4c = truncatedSha256Hex(extensionsString)
        } else {
            ja4c = truncatedSha256Hex("\(extensionsString)_\(signatureAlgorithmsString)")
        }

        return "\(ja4a)_\(ja4b)_\(ja4c)"
    }
}

private func isGREASEUint16(_ value: UInt16) -> Bool {
    return (value >> 8) == (value & 0xff) && (value & 0xf) == 0xa
}

private func tlsVersionString(tlsVersion: Int32) -> String {
    switch tlsVersion {
    case TLS1_3_VERSION:
        return "13"
    case TLS1_2_VERSION:
        return "12"
    case TLS1_1_VERSION:
        return "11"
    case TLS1_VERSION:
        return "10"
    default:
        return "00"
    }
}

private func truncatedSha256Hex(_ input: String) -> String {
    let inputBytes = Array(input.utf8)
    var hashBytes = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
    inputBytes.withUnsafeBufferPointer { buffer in
        _ = CNIOBoringSSL_SHA256(buffer.baseAddress, buffer.count, &hashBytes)
    }
    return hashBytes.prefix(12).map { String(format: "%02x", $0) }.joined()
}
