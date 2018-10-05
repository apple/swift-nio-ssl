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

import NIO
import CNIOOpenSSL

// This is a neat trick. Swift lazily initializes module-globals based on when they're first
// used. This lets us defer OpenSSL intialization as late as possible and only do it if people
// actually create any object that uses OpenSSL.
internal var openSSLIsInitialized: Bool = initializeOpenSSL()

private enum FileSystemObject {
    case directory
    case file

    static func pathType(path: String) -> FileSystemObject? {
        var statObj = stat()
        do {
            try Posix.stat(path: path, buf: &statObj)
        } catch {
            return nil
        }

#if os(Android)
        return (statObj.st_mode & UInt32(Glibc.S_IFDIR)) != 0 ? .directory : .file
#else
        return (statObj.st_mode & S_IFDIR) != 0 ? .directory : .file
#endif
    }
}

// This bizarre extension to UnsafeBufferPointer is very useful for handling ALPN identifiers. OpenSSL
// likes to work with them in wire format, so rather than us decoding them we can just encode ours to
// the wire format and then work with them from there.
private extension UnsafeBufferPointer where Element == UInt8 {
    func locateAlpnIdentifier<T>(identifier: UnsafeBufferPointer<T>) -> (index: Int, length: Int)? where T == Element {
        precondition(identifier.count != 0)
        let targetLength = Int(identifier[0])

        var index = 0
        outerLoop: while index < self.count {
            let length = Int(self[index])
            guard index + length + 1 <= self.count else {
                // Invalid length of ALPN identifier, no match.
                return nil
            }

            guard targetLength == length else {
                index += length + 1
                continue outerLoop
            }

            for innerIndex in 1...length {
                guard identifier[innerIndex] == self[index + innerIndex] else {
                    index += length + 1
                    continue outerLoop
                }
            }

            // Found it
            return (index: index + 1, length: length)
        }
        return nil
    }
}

private func alpnCallback(ssl: OpaquePointer?,
                          out: UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
                          outlen: UnsafeMutablePointer<UInt8>?,
                          in: UnsafePointer<UInt8>?,
                          inlen: UInt32,
                          appData: UnsafeMutableRawPointer?) -> Int32 {
    // Perform some sanity checks. We don't want NULL pointers around here.
    guard let ssl = ssl, let out = out, let outlen = outlen, let `in` = `in` else {
        return SSL_TLSEXT_ERR_ALERT_FATAL
    }

    // We want to take the SSL pointer and extract the parent Swift object.
    let parentCtx = SSL_get_SSL_CTX(.make(optional: ssl))!
    let parentPtr = CNIOOpenSSL_SSL_CTX_get_app_data(parentCtx)!
    let parentSwiftContext: SSLContext = Unmanaged.fromOpaque(parentPtr).takeUnretainedValue()

    let offeredProtocols = UnsafeBufferPointer(start: `in`, count: Int(inlen))
    guard let (index, length) = parentSwiftContext.alpnSelectCallback(offeredProtocols: offeredProtocols) else {
        out.pointee = nil
        outlen.pointee = 0
        return SSL_TLSEXT_ERR_ALERT_FATAL
    }

    out.pointee = `in` + index
    outlen.pointee = UInt8(length)
    return SSL_TLSEXT_ERR_OK
}

/// A wrapper class that encapsulates OpenSSL's `SSL_CTX *` object.
///
/// This class represents configuration for a collection of TLS connections, all of
/// which are expected to be broadly the same.
public final class SSLContext {
    private let sslContext: OpaquePointer
    private let callbackManager: CallbackManagerProtocol?
    internal let configuration: TLSConfiguration

    /// Initialize a context that will create multiple connections, all with the same
    /// configuration.
    internal init(configuration: TLSConfiguration, callbackManager: CallbackManagerProtocol?) throws {
        guard openSSLIsInitialized else { fatalError("Failed to initialize OpenSSL") }
        guard let ctx = SSL_CTX_new(CNIOOpenSSL_TLS_Method()) else { throw NIOOpenSSLError.unableToAllocateOpenSSLObject }

        // TODO(cory): It doesn't seem like this initialization should happen here: where?
        CNIOOpenSSL_SSL_CTX_setAutoECDH(ctx)

        // First, let's set some basic modes. We set the following:
        // - SSL_MODE_RELEASE_BUFFERS: Because this can save a bunch of memory on idle connections.
        // - SSL_MODE_AUTO_RETRY: Because OpenSSL's default behaviour on SSL_read without this flag is bad.
        //     See https://github.com/openssl/openssl/issues/6234 for more discussion on this.
        CNIOOpenSSL_SSL_CTX_set_mode(ctx, Int(SSL_MODE_RELEASE_BUFFERS | SSL_MODE_AUTO_RETRY))

        var opensslOptions = Int(SSL_OP_NO_COMPRESSION)

        // Handle TLS versions
        switch configuration.minimumTLSVersion {
        case .tlsv13:
            opensslOptions |= Int(SSL_OP_NO_TLSv1_2)
            fallthrough
        case .tlsv12:
            opensslOptions |= Int(SSL_OP_NO_TLSv1_1)
            fallthrough
        case .tlsv11:
            opensslOptions |= Int(SSL_OP_NO_TLSv1)
            fallthrough
        case .tlsv1:
            opensslOptions |= Int(SSL_OP_NO_SSLv3)
            fallthrough
        case .sslv3:
            opensslOptions |= Int(SSL_OP_NO_SSLv2)
            fallthrough
        case .sslv2:
            break
        }

        switch configuration.maximumTLSVersion {
        case .some(.sslv2):
            opensslOptions |= Int(SSL_OP_NO_SSLv3)
            fallthrough
        case .some(.sslv3):
            opensslOptions |= Int(SSL_OP_NO_TLSv1)
            fallthrough
        case .some(.tlsv1):
            opensslOptions |= Int(SSL_OP_NO_TLSv1_1)
            fallthrough
        case .some(.tlsv11):
            opensslOptions |= Int(SSL_OP_NO_TLSv1_2)
            fallthrough
        case .some(.tlsv12):
            opensslOptions |= Int(CNIOOpenSSL_SSL_OP_NO_TLSv1_3)
        case .some(.tlsv13), .none:
            break
        }

        // It's not really very clear here, but this is the actual way to spell SSL_CTX_set_options in Swift code.
        // Sadly, SSL_CTX_set_options is a macro, which means we cannot use it directly, and our modulemap doesn't
        // reveal it in a helpful way, so we write it like this instead.
        CNIOOpenSSL_SSL_CTX_set_options(ctx, opensslOptions)

        // Cipher suites. We just pass this straight to OpenSSL.
        let tls12ReturnCode = SSL_CTX_set_cipher_list(ctx, configuration.cipherSuites)
        precondition(1 == tls12ReturnCode)
        let tls13ReturnCode = CNIOOpenSSL_SSL_CTX_set_ciphersuites(ctx, configuration.tls13CipherSuites)
        precondition(1 == tls13ReturnCode)

        // If validation is turned on, set the trust roots and turn on cert validation.
        switch configuration.certificateVerification {
        case .fullVerification, .noHostnameVerification:
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, CNIOOpenSSL_noop_verify_callback)

            switch configuration.trustRoots {
            case .some(.default), .none:
                precondition(1 == SSL_CTX_set_default_verify_paths(ctx))
            case .some(.file(let f)):
                try SSLContext.loadVerifyLocations(f, context: .init(ctx))
            case .some(.certificates(let certs)):
                try certs.forEach { try SSLContext.addRootCertificate($0, context: .init(ctx)) }
            }
        default:
            break
        }

        // If we were given a certificate chain to use, load it and its associated private key. Before
        // we do, set up a passphrase callback if we need to.
        if let callbackManager = callbackManager {
            SSL_CTX_set_default_passwd_cb(ctx, globalOpenSSLPassphraseCallback(buf:size:rwflag:u:))
            SSL_CTX_set_default_passwd_cb_userdata(ctx, Unmanaged.passUnretained(callbackManager as AnyObject).toOpaque())
        }

        var leaf = true
        try configuration.certificateChain.forEach {
            switch $0 {
            case .file(let p):
                SSLContext.useCertificateChainFile(p, context: .init(ctx))
                leaf = false
            case .certificate(let cert):
                if leaf {
                    try SSLContext.setLeafCertificate(cert, context: .init(ctx))
                    leaf = false
                } else {
                    try SSLContext.addAdditionalChainCertificate(cert, context: .init(ctx))
                }
            }
        }

        if let pkey = configuration.privateKey {
            switch pkey {
            case .file(let p):
                SSLContext.usePrivateKeyFile(p, context: .init(ctx))
            case .privateKey(let key):
                try SSLContext.setPrivateKey(key, context: .init(ctx))
            }
        }

        if configuration.applicationProtocols.count > 0 {
            try SSLContext.setAlpnProtocols(configuration.applicationProtocols, context: .init(ctx))
            SSLContext.setAlpnCallback(context: .init(ctx))
        }

        self.sslContext = .init(ctx)
        self.configuration = configuration
        self.callbackManager = callbackManager

        // Always make it possible to get from an SSL_CTX structure back to this.
        let ptrToSelf = Unmanaged.passUnretained(self).toOpaque()
        CNIOOpenSSL_SSL_CTX_set_app_data(ctx, ptrToSelf)
    }

    /// Initialize a context that will create multiple connections, all with the same
    /// configuration.
    public convenience init(configuration: TLSConfiguration) throws {
        try self.init(configuration: configuration, callbackManager: nil)
    }

    /// Initialize a context that will create multiple connections, all with the same
    /// configuration, along with a callback that will be called when needed to decrypt any
    /// encrypted private keys.
    ///
    /// - parameters:
    ///     - configuration: The `TLSConfiguration` to use for all the connections with this
    ///         `SSLContext`.
    ///     - passphraseCallback: The callback to use to decrypt any private keys used by this
    ///         `SSLContext`. For more details on this parameter see the documentation for
    ///         `OpenSSLPassphraseCallback`.
    public convenience init<T: Collection>(configuration: TLSConfiguration,
                                           passphraseCallback: @escaping OpenSSLPassphraseCallback<T>) throws where T.Element == UInt8 {
        let manager = OpenSSLPassphraseCallbackManager(userCallback: passphraseCallback)
        try self.init(configuration: configuration, callbackManager: manager)
    }

    /// Create a new connection object with the configuration from this
    /// context.
    internal func createConnection() -> SSLConnection? {
        guard let ssl = SSL_new(.make(optional: sslContext)) else {
            return nil
        }
        return SSLConnection(ownedSSL: .init(ssl), parentContext: self)
    }

    fileprivate func alpnSelectCallback(offeredProtocols: UnsafeBufferPointer<UInt8>) ->  (index: Int, length: Int)? {
        for possibility in configuration.applicationProtocols {
            let match = possibility.withUnsafeBufferPointer {
                offeredProtocols.locateAlpnIdentifier(identifier: $0)
            }
            if match != nil { return match }
        }

        return nil
    }

    deinit {
        SSL_CTX_free(.make(optional: sslContext))
    }
}


extension SSLContext {
    private static func useCertificateChainFile(_ path: String, context: OpaquePointer) {
        // TODO(cory): This shouldn't be an assert but should instead be actual error handling.
        // assert(path.isFileURL)
        let result = path.withCString { (pointer) -> Int32 in
            return SSL_CTX_use_certificate_chain_file(.make(optional: context), pointer)
        }
        
        // TODO(cory): again, some error handling would be good.
        precondition(result == 1)
    }

    private static func setLeafCertificate(_ cert: OpenSSLCertificate, context: OpaquePointer) throws {
        let rc = SSL_CTX_use_certificate(.make(optional: context), .make(optional: cert.ref))
        guard rc == 1 else {
            throw NIOOpenSSLError.failedToLoadCertificate
        }
    }
    
    private static func addAdditionalChainCertificate(_ cert: OpenSSLCertificate, context: OpaquePointer) throws {
        // This dup is necessary because the SSL_CTX_ctrl doesn't copy the X509 object itself.
        guard 1 == SSL_CTX_ctrl(.make(optional: context), SSL_CTRL_EXTRA_CHAIN_CERT, 0, .init(X509_dup(.make(optional: cert.ref)))) else {
            throw NIOOpenSSLError.failedToLoadCertificate
        }
    }
    
    private static func setPrivateKey(_ key: OpenSSLPrivateKey, context: OpaquePointer) throws {
        guard 1 == SSL_CTX_use_PrivateKey(.make(optional: context), .make(optional: key.ref)) else {
            throw NIOOpenSSLError.failedToLoadPrivateKey
        }
    }
    
    private static func addRootCertificate(_ cert: OpenSSLCertificate, context: OpaquePointer) throws {
        let store = SSL_CTX_get_cert_store(.make(optional: context))!
        if 0 == X509_STORE_add_cert(store, .make(optional: cert.ref)) {
            throw NIOOpenSSLError.failedToLoadCertificate
        }
    }
    
    private static func usePrivateKeyFile(_ path: String, context: OpaquePointer) {
        let pathExtension = path.split(separator: ".").last
        let fileType: Int32
        
        switch pathExtension?.lowercased() {
        case .some("pem"):
            fileType = SSL_FILETYPE_PEM
        case .some("der"), .some("key"):
            fileType = SSL_FILETYPE_ASN1
        default:
            // TODO(cory): Again, error handling here would be good.
            fatalError("Unknown private key file type.")
        }
        
        let result = path.withCString { (pointer) -> Int32 in
            return SSL_CTX_use_PrivateKey_file(.make(optional: context), pointer, fileType)
        }
        
        // TODO(cory): again, some error handling would be good.
        precondition(result == 1)
    }
    
    private static func loadVerifyLocations(_ path: String, context: OpaquePointer) throws {
        let isDirectory: Bool
        switch FileSystemObject.pathType(path: path) {
        case .some(.directory):
            isDirectory = true
        case .some(.file):
            isDirectory = false
        case .none:
            throw NIOOpenSSLError.noSuchFilesystemObject
        }
        
        let result = path.withCString { (pointer) -> Int32 in
            let file = !isDirectory ? pointer : nil
            let directory = isDirectory ? pointer: nil
            return SSL_CTX_load_verify_locations(.make(optional: context), file, directory)
        }
        
        if result == 0 {
            let errorStack = OpenSSLError.buildErrorStack()
            throw OpenSSLError.unknownError(errorStack)
        }
    }

    private static func setAlpnProtocols(_ protocols: [[UInt8]], context: OpaquePointer) throws {
        // This copy should be done infrequently, so we don't worry too much about it.
        let protoBuf = protocols.reduce([UInt8](), +)
        let rc = protoBuf.withUnsafeBufferPointer {
            CNIOOpenSSL_SSL_CTX_set_alpn_protos(.make(optional: context), $0.baseAddress!, UInt32($0.count))
        }

        // Annoyingly this function reverses the error convention: 0 is success, non-zero is failure.
        if rc != 0 {
            let errorStack = OpenSSLError.buildErrorStack()
            throw OpenSSLError.failedToSetALPN(errorStack)
        }
    }

    private static func setAlpnCallback(context: OpaquePointer) {
        // This extra closure here is very silly, but it exists to allow us to avoid writing down the type of the first
        // argument. Combined with the helper above, the compiler will be able to solve its way to success here.
        CNIOOpenSSL_SSL_CTX_set_alpn_select_cb(.make(optional: context),
                                               { alpnCallback(ssl: .make(optional: $0), out: $1, outlen: $2, in: $3, inlen: $4, appData: $5) },
                                               nil)
    }
}
