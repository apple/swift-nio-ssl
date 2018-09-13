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

/// Initialize OpenSSL. Note that this function IS NOT THREAD SAFE, and so must be called inside
/// either an explicit or implicit dispatch_once.
func initializeOpenSSL() -> Bool {
    // Initializing OpenSSL is made up of two steps. First, we need to load all the various crypto bits.
    CNIOOpenSSL_InitializeOpenSSL()

    // Now we need to set up our custom BIO.
    setupBIO()
    return true
}

/// Called to initialize our custom OpenSSL BIO.
private func setupBIO() {
    /// If the BIO is already initialized, don't do it again.
    guard CNIOOpenSSL_ByteBufferBIOType == 0 else {
        return
    }
    CNIOOpenSSL_initByteBufferBIO(openSSLBIOWriteFunc, openSSLBIOReadFunc,
                                  openSSLBIOPutsFunc, openSSLBIOGetsFunc,
                                  openSSLBIOCtrlFunc, openSSLBIOCreateFunc,
                                  openSSLBIODestroyFunc)
}
