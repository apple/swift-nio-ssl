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
import NIO

/// Wraps a single error from OpenSSL.
public struct OpenSSLInternalError: Equatable, CustomStringConvertible {
    let errorCode: u_long

    var errorMessage: String? {
        if let cErrorMessage = ERR_error_string(errorCode, nil) {
            return String.init(cString: cErrorMessage)
        }
        return nil
    }

    public var description: String {
        return "Error: \(errorCode) \(errorMessage ?? "")"
    }

    init(errorCode: u_long) {
        self.errorCode = errorCode
    }

    public static func ==(lhs: OpenSSLInternalError, rhs: OpenSSLInternalError) -> Bool {
        return lhs.errorCode == rhs.errorCode
    }

}

/// A representation of OpenSSL's internal error stack: a list of OpenSSL errors.
public typealias OpenSSLErrorStack = [OpenSSLInternalError]


/// Errors that can be raised by NIO's OpenSSL wrapper.
public enum NIOOpenSSLError: Error {
    case writeDuringTLSShutdown
    case unableToAllocateOpenSSLObject
    case noSuchFilesystemObject
    case failedToLoadCertificate
    case failedToLoadPrivateKey
    case handshakeFailed(OpenSSLError)
    case shutdownFailed(OpenSSLError)
    case cannotMatchULabel
    case noCertificateToValidate
    case unableToValidateCertificate
    case cannotFindPeerIP
    case readInInvalidTLSState
}

extension NIOOpenSSLError: Equatable {
    public static func ==(lhs: NIOOpenSSLError, rhs: NIOOpenSSLError) -> Bool {
        switch (lhs, rhs) {
        case (.writeDuringTLSShutdown, .writeDuringTLSShutdown),
             (.unableToAllocateOpenSSLObject, .unableToAllocateOpenSSLObject),
             (.noSuchFilesystemObject, .noSuchFilesystemObject),
             (.failedToLoadCertificate, .failedToLoadCertificate),
             (.failedToLoadPrivateKey, .failedToLoadPrivateKey),
             (.cannotMatchULabel, .cannotMatchULabel),
             (.noCertificateToValidate, .noCertificateToValidate),
             (.unableToValidateCertificate, .unableToValidateCertificate):
            return true
        case (.handshakeFailed(let err1), .handshakeFailed(let err2)),
             (.shutdownFailed(let err1), .shutdownFailed(let err2)):
            return err1 == err2
        default:
            return false
        }
    }
}

/// An enum that wraps individual OpenSSL errors directly.
public enum OpenSSLError: Error {
    case noError
    case zeroReturn
    case wantRead
    case wantWrite
    case wantConnect
    case wantAccept
    case wantX509Lookup
    case syscallError
    case sslError(OpenSSLErrorStack)
    case unknownError(OpenSSLErrorStack)
    case uncleanShutdown
    case invalidSNIName(OpenSSLErrorStack)
    case failedToSetALPN(OpenSSLErrorStack)
}

extension OpenSSLError: Equatable {}

public func ==(lhs: OpenSSLError, rhs: OpenSSLError) -> Bool {
    switch (lhs, rhs) {
    case (.noError, .noError),
         (.zeroReturn, .zeroReturn),
         (.wantRead, .wantRead),
         (.wantWrite, .wantWrite),
         (.wantConnect, .wantConnect),
         (.wantAccept, .wantAccept),
         (.wantX509Lookup, .wantX509Lookup),
         (.syscallError, .syscallError),
         (.uncleanShutdown, .uncleanShutdown):
        return true
    case (.sslError(let e1), .sslError(let e2)),
         (.unknownError(let e1), .unknownError(let e2)):
        return e1 == e2
    default:
        return false
    }
}

internal extension OpenSSLError {
    static func fromSSLGetErrorResult(_ result: Int32) -> OpenSSLError? {
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
    
    static func buildErrorStack() -> OpenSSLErrorStack {
        var errorStack = OpenSSLErrorStack()
        
        while true {
            let errorCode = ERR_get_error()
            if errorCode == 0 { break }
            errorStack.append(OpenSSLInternalError(errorCode: errorCode))
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
