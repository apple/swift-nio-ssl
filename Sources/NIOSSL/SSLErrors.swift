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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif

/// Wraps a single error from BoringSSL.
public struct BoringSSLInternalError: Equatable, CustomStringConvertible {
    let errorCode: UInt32

    var errorMessage: String? {
        // TODO(cory): This should become non-optional in the future, as it always succeeds.
        var scratchBuffer = [CChar](repeating: 0, count: 512)
        return scratchBuffer.withUnsafeMutableBufferPointer { pointer in
            CNIOBoringSSL_ERR_error_string_n(self.errorCode, pointer.baseAddress!, pointer.count)
            return String(cString: pointer.baseAddress!)
        }
    }

    public var description: String {
        return "Error: \(errorCode) \(errorMessage ?? "")"
    }

    init(errorCode: UInt32) {
        self.errorCode = errorCode
    }
}

/// A representation of BoringSSL's internal error stack: a list of BoringSSL errors.
public typealias NIOBoringSSLErrorStack = [BoringSSLInternalError]


/// Errors that can be raised by NIO's BoringSSL wrapper.
public enum NIOSSLError: Error {
    case writeDuringTLSShutdown
    @available(*, deprecated, message: "unableToAllocateBoringSSLObject can no longer be thrown")
    case unableToAllocateBoringSSLObject
    case noSuchFilesystemObject
    case failedToLoadCertificate
    case failedToLoadPrivateKey
    case handshakeFailed(BoringSSLError)
    case shutdownFailed(BoringSSLError)
    case cannotMatchULabel
    case noCertificateToValidate
    case unableToValidateCertificate
    case cannotFindPeerIP
    case readInInvalidTLSState
    case uncleanShutdown
}

extension NIOSSLError: Equatable {}

/// Closing the TLS channel cleanly timed out, so it was closed uncleanly.
public struct NIOSSLCloseTimedOutError: Error {}

/// An enum that wraps individual BoringSSL errors directly.
public enum BoringSSLError: Error {
    case noError
    case zeroReturn
    case wantRead
    case wantWrite
    case wantConnect
    case wantAccept
    case wantX509Lookup
    case wantCertificateVerify
    case syscallError
    case sslError(NIOBoringSSLErrorStack)
    case unknownError(NIOBoringSSLErrorStack)
    case invalidSNIName(NIOBoringSSLErrorStack)
    case failedToSetALPN(NIOBoringSSLErrorStack)
}

extension BoringSSLError: Equatable {}


internal extension BoringSSLError {
    static func fromSSLGetErrorResult(_ result: CInt) -> BoringSSLError? {
        switch result {
        case SSL_ERROR_NONE:
            return .noError
        case SSL_ERROR_ZERO_RETURN:
            return .zeroReturn
        case SSL_ERROR_WANT_READ:
            return .wantRead
        case SSL_ERROR_WANT_WRITE:
            return .wantWrite
        case SSL_ERROR_WANT_CONNECT:
            return .wantConnect
        case SSL_ERROR_WANT_ACCEPT:
            return .wantAccept
        case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
            return .wantCertificateVerify
        case SSL_ERROR_WANT_X509_LOOKUP:
            return .wantX509Lookup
        case SSL_ERROR_SYSCALL:
            return .syscallError
        case SSL_ERROR_SSL:
            return .sslError(buildErrorStack())
        default:
            return .unknownError(buildErrorStack())
        }
    }
    
    static func buildErrorStack() -> NIOBoringSSLErrorStack {
        var errorStack = NIOBoringSSLErrorStack()
        
        while true {
            let errorCode = CNIOBoringSSL_ERR_get_error()
            if errorCode == 0 { break }
            errorStack.append(BoringSSLInternalError(errorCode: errorCode))
        }
        
        return errorStack
    }
}

/// Represents errors that may occur while attempting to unwrap TLS from a connection.
public enum NIOTLSUnwrappingError: Error {
    /// The TLS channel has already been closed, so it is not possible to unwrap it.
    case alreadyClosed

    /// The internal state of the handler is not able to process the unwrapping request.
    case invalidInternalState

    /// We were unwrapping the connection, but during the unwrap process a close call
    /// was made. This means the connection is now closed, not unwrapped.
    case closeRequestedDuringUnwrap

    /// This write was failed because the channel was unwrapped before it was flushed.
    case unflushedWriteOnUnwrap
}


/// This structure contains errors added to NIOSSL after the original `NIOSSLError` enum was
/// shipped. This is an extensible error object that allows us to evolve it going forward.
public struct NIOSSLExtraError: Error {
    private var baseError: NIOSSLExtraError.BaseError

    private var _description: String?

    private init(baseError: NIOSSLExtraError.BaseError, description: String?) {
        self.baseError = baseError
        self._description = description
    }
}


extension NIOSSLExtraError {
    private enum BaseError: Equatable {
        case failedToValidateHostname
        case serverHostnameImpossibleToMatch
        case cannotUseIPAddressInSNI
        case invalidSNIHostname
    }
}


extension NIOSSLExtraError {
    /// NIOSSL was unable to validate the hostname presented by the remote peer.
    public static let failedToValidateHostname = NIOSSLExtraError(baseError: .failedToValidateHostname, description: nil)

    /// The server hostname provided by the user cannot match any names in the certificate due to containing invalid characters.
    public static let serverHostnameImpossibleToMatch = NIOSSLExtraError(baseError: .serverHostnameImpossibleToMatch, description: nil)

    /// IP addresses may not be used in SNI.
    public static let cannotUseIPAddressInSNI = NIOSSLExtraError(baseError: .cannotUseIPAddressInSNI, description: nil)

    /// The SNI hostname requirements have not been met.
    ///
    /// - note: Should the provided SNI hostname be an IP address instead, `.cannotUseIPAddressInSNI` is thrown instead
    ///         of this error.
    ///
    /// Reasons a hostname might not meet the requirements:
    /// - hostname in UTF8 is more than 255 bytes
    /// - hostname is the empty string
    /// - hostname contains the `0` unicode scalar (which would be encoded as the `0` byte which is unsupported).
    public static let invalidSNIHostname = NIOSSLExtraError(baseError: .invalidSNIHostname, description: nil)

    @inline(never)
    internal static func failedToValidateHostname(expectedName: String) -> NIOSSLExtraError {
        let description = "Couldn't find \(expectedName) in certificate from peer"
        return NIOSSLExtraError(baseError: .failedToValidateHostname, description: description)
    }

    @inline(never)
    internal static func serverHostnameImpossibleToMatch(hostname: String) -> NIOSSLExtraError {
        let description = "The server hostname \(hostname) cannot be matched due to containing non-DNS characters"
        return NIOSSLExtraError(baseError: .serverHostnameImpossibleToMatch, description: description)
    }

    @inline(never)
    internal static func cannotUseIPAddressInSNI(ipAddress: String) -> NIOSSLExtraError {
        let description = "IP addresses cannot validly be used for Server Name Indication, got \(ipAddress)"
        return NIOSSLExtraError(baseError: .cannotUseIPAddressInSNI, description: description)
    }
}


extension NIOSSLExtraError: CustomStringConvertible {
    public var description: String {
        let formattedDescription = self._description.map { ": " + $0 } ?? ""
        return "NIOSSLExtraError.\(String(describing: self.baseError))\(formattedDescription)"
    }
}

extension NIOSSLExtraError: Equatable {
    public static func ==(lhs: NIOSSLExtraError, rhs: NIOSSLExtraError) -> Bool {
        return lhs.baseError == rhs.baseError
    }
}
