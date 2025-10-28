//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
@_implementationOnly import CNIOBoringSSL

enum UnsafeKeyAndChainTarget {
    case sslContext(OpaquePointer)
    case ssl(OpaquePointer)

    func useCertificateChain(
        _ certificateChain: [NIOSSLCertificateSource]
    ) throws {
        // Clear the existing chain first.
        // So that when this function is called, `certificateChain` becomes the only certificates in the context.
        self.clearAdditionalChainCertificates()
        var leaf = true
        for source in certificateChain {
            switch source {
            case .file(let p):
                self.useCertificateChainFile(p)
                leaf = false
            case .certificate(let cert):
                if leaf {
                    try self.setLeafCertificate(cert)
                    leaf = false
                } else {
                    try self.addAdditionalChainCertificate(cert)
                }
            }
        }
    }

    func useCertificateChainFile(_ path: String) {
        let result = path.withCString { (pointer) -> CInt in
            switch self {
            case .sslContext(let context):
                CNIOBoringSSL_SSL_CTX_use_certificate_chain_file(context, pointer)
            case .ssl(let ssl):
                CNIOBoringSSL_SSL_CTX_use_certificate_chain_file(ssl, pointer)
            }
        }

        precondition(result == 1)
    }

    func setLeafCertificate(_ cert: NIOSSLCertificate) throws {
        let rc = cert.withUnsafeMutableX509Pointer { ref in
            switch self {
            case .sslContext(let context):
                CNIOBoringSSL_SSL_CTX_use_certificate(context, ref)
            case .ssl(let ssl):
                CNIOBoringSSL_SSL_use_certificate(ssl, ref)
            }
        }
        guard rc == 1 else {
            throw NIOSSLError.failedToLoadCertificate
        }
    }

    func clearAdditionalChainCertificates() {
        switch self {
        case .sslContext(let context):
            CNIOBoringSSL_SSL_CTX_clear_chain_certs(context)
        case .ssl(let ssl):
            CNIOBoringSSL_SSL_clear_chain_certs(ssl)
        }
    }

    func addAdditionalChainCertificate(_ cert: NIOSSLCertificate) throws {
        let rc = cert.withUnsafeMutableX509Pointer { ref in
            switch self {
            case .sslContext(let context):
                CNIOBoringSSL_SSL_CTX_add1_chain_cert(context, ref)
            case .ssl(let ssl):
                CNIOBoringSSL_SSL_add1_chain_cert(ssl, ref)
            }
        }
        guard rc == 1 else {
            throw NIOSSLError.failedToLoadCertificate
        }
    }

    func usePrivateKeySource(_ privateKey: NIOSSLPrivateKeySource) throws {
        switch privateKey {
        case .file(let p):
            try self.usePrivateKeyFile(p)
        case .privateKey(let key):
            try self.setPrivateKey(key)
        }
    }

    func setPrivateKey(_ key: NIOSSLPrivateKey) throws {
        switch key.representation {
        case .native:
            let rc = key.withUnsafeMutableEVPPKEYPointer { ref in
                switch self {
                case .sslContext(let context):
                    CNIOBoringSSL_SSL_CTX_use_PrivateKey(context, ref)
                case .ssl(let ssl):
                    CNIOBoringSSL_SSL_use_PrivateKey(ssl, ref)
                }
            }
            guard 1 == rc else {
                throw NIOSSLError.failedToLoadPrivateKey
            }
        case .custom:
            switch self {
            case .sslContext(let context):
                CNIOBoringSSL_SSL_CTX_set_private_key_method(context, customPrivateKeyMethod)
            case .ssl(let ssl):
                CNIOBoringSSL_SSL_set_private_key_method(ssl, customPrivateKeyMethod)
            }
        }
    }

    func usePrivateKeyFile(_ path: String) throws {
        let pathExtension = path.split(separator: ".").last
        let fileType: CInt

        switch pathExtension?.lowercased() {
        case .some("pem"):
            fileType = SSL_FILETYPE_PEM
        case .some("der"), .some("key"):
            fileType = SSL_FILETYPE_ASN1
        default:
            throw NIOSSLExtraError.unknownPrivateKeyFileType(path: path)
        }

        let result = path.withCString { (pointer) -> CInt in
            switch self {
            case .sslContext(let context):
                CNIOBoringSSL_SSL_CTX_use_PrivateKey_file(context, pointer, fileType)
            case .ssl(let ssl):
                CNIOBoringSSL_SSL_use_PrivateKey_file(ssl, pointer, fileType)
            }
        }

        guard result == 1 else {
            throw NIOSSLError.failedToLoadPrivateKey
        }
    }
}
