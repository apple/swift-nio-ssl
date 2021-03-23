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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif

// We can only use Security.framework to validate TLS certificates on Apple platforms.
#if os(macOS) || os(iOS) || os(watchOS) || os(tvOS)
import Dispatch
import Foundation
import Security

extension SSLConnection {
    func performSecurityFrameworkValidation(promise: EventLoopPromise<NIOSSLVerificationResult>) {
        do {
            guard case .default = self.parentContext.configuration.trustRoots ?? .default else {
                preconditionFailure("This callback should only be used if we are using the system-default trust.")
            }

            // Ok, time to kick off a validation. Let's get some certificate buffers.
            let peerCertificates: [SecCertificate] = try self.withPeerCertificateChainBuffers { buffers in
                guard let buffers = buffers else {
                    throw NIOSSLError.unableToValidateCertificate
                }

                return try buffers.map { buffer in
                    let data = Data(bytes: buffer.baseAddress!, count: buffer.count)
                    guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
                        throw NIOSSLError.unableToValidateCertificate
                    }
                    return cert
                }
            }

            // This force-unwrap is safe as we must have decided if we're a client or a server before validation.
            var trust: SecTrust? = nil
            var result: OSStatus
            let policy = SecPolicyCreateSSL(self.role! == .client, self.expectedHostname as CFString?)
            result = SecTrustCreateWithCertificates(peerCertificates as CFArray, policy, &trust)
            guard result == errSecSuccess, let actualTrust = trust else {
                throw NIOSSLError.unableToValidateCertificate
            }

            // If there are additional trust roots then we need to add them to the SecTrust as anchors.
            let additionalAnchorCertificates: [SecCertificate] = try self.parentContext.configuration.additionalTrustRoots.flatMap { trustRoots -> [NIOSSLCertificate] in
                guard case .certificates(let certs) = trustRoots else {
                    preconditionFailure("This callback happens on the request path, file-based additional trust roots should be pre-loaded when creating the SSLContext.")
                }
                return certs
            }.map {
                guard let secCert = SecCertificateCreateWithData(nil, Data(try $0.toDERBytes()) as CFData) else {
                    throw NIOSSLError.failedToLoadCertificate
                }
                return secCert
            }
            if !additionalAnchorCertificates.isEmpty {
                // To use additional anchors _and_ the built-in ones we must reenable the built-in ones expicitly.
                guard SecTrustSetAnchorCertificatesOnly(actualTrust, false) == errSecSuccess else {
                    throw NIOSSLError.failedToLoadCertificate
                }
                guard SecTrustSetAnchorCertificates(actualTrust, additionalAnchorCertificates as CFArray) == errSecSuccess else {
                    throw NIOSSLError.failedToLoadCertificate
                }
            }

            // We create a DispatchQueue here to be called back on, as this validation may perform network activity.
            let callbackQueue = DispatchQueue(label: "io.swiftnio.ssl.validationCallbackQueue")

            // SecTrustEvaluateAsync and its cousin withError require that they are called from the same queue given to
            // them as a parameter. Thus, we async away now.
            callbackQueue.async {
                let result: OSStatus

                if #available(iOS 13, macOS 10.15, tvOS 13, watchOS 6, *) {
                    result = SecTrustEvaluateAsyncWithError(actualTrust, callbackQueue) { (_, valid, _) in
                        promise.succeed(valid ? .certificateVerified : .failed)
                    }
                } else {
                    result = SecTrustEvaluateAsync(actualTrust, callbackQueue) { (_, result) in
                        promise.completeWith(result)
                    }
                }

                if result != errSecSuccess {
                    promise.fail(NIOSSLError.unableToValidateCertificate)
                }
            }
        } catch {
            promise.fail(error)
        }
    }
}

extension EventLoopPromise where Value == NIOSSLVerificationResult {
    fileprivate func completeWith(_ result: SecTrustResultType) {
        switch result {
        case .proceed, .unspecified:
            // These two cases mean we have successfully validated the certificate. We're done!
            self.succeed(.certificateVerified)
        default:
            // Oops, we failed.
            self.succeed(.failed)
        }
    }
}

#endif
