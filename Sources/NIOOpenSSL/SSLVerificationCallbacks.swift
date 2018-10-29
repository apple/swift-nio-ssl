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

/// The result of an attempt to verify an X.509 certificate.
public enum OpenSSLVerificationResult {
    /// The certificate was successfully verified.
    case certificateVerified

    /// The certificate was not verified.
    case failed

    internal init(fromOpenSSLPreverify preverify: CInt) {
        switch preverify {
        case 1:
            self = .certificateVerified
        case 0:
            self = .failed
        default:
            preconditionFailure("Invalid preverify value: \(preverify)")
        }
    }
}

/// A custom verification callback.
///
/// This verification callback is usually called more than once per connection, as it is called once
/// per certificate in the peer's complete certificate chain (including the root CA). The calls proceed
/// from root to leaf, ending with the peer's leaf certificate. Each time it is invoked with 2 arguments:
///
/// 1. The result of the OpenSSL verification for this certificate
/// 2. The `SSLCertificate` for this level of the chain.
///
/// Please be cautious with calling out from this method. This method is always invoked on the event loop,
/// so you must not block or wait. It is not possible to return an `EventLoopFuture` from this method, as it
/// must not block or wait. Additionally, this method must take care to ensure that it does not cause any
/// ChannelHandler to recursively call back into the `OpenSSLHandler` that triggered it, as making re-entrant
/// calls into OpenSSL is not supported by SwiftNIO and leads to undefined behaviour.
///
/// In general, the only safe thing to do here is to either perform some cryptographic operations, to log,
/// or to store the `OpenSSLCertificate` somewhere for later consumption. The easiest way to be sure that the
/// `OpenSSLCertificate` is safe to consume is to wait for a user event that shows the handshake as completed,
/// or for channelInactive.
public typealias OpenSSLVerificationCallback = (OpenSSLVerificationResult, OpenSSLCertificate) -> OpenSSLVerificationResult
