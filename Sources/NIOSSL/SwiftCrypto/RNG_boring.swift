//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

extension UnsafeMutableRawBufferPointer {
    func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= self.count)
        var rng = SystemRandomNumberGenerator()

        // We store bytes 64-bits at a time until we can't anymore.
        var targetPtr = self
        while targetPtr.count > 8 {
            targetPtr.storeBytes(of: rng.next(), as: UInt64.self)
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[8...])
        }

        // Now we're down to having to store things an integer at a time. We do this by shifting and
        // masking.
        var remainingWord: UInt64 = rng.next()
        while targetPtr.count > 0 {
            targetPtr.storeBytes(of: UInt8(remainingWord & 0xFF), as: UInt8.self)
            remainingWord >>= 8
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[1...])
        }
    }
}
