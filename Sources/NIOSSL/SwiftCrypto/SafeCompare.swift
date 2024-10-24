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

/// A straightforward constant-time comparison function for any two collections of bytes.
@inlinable
internal func constantTimeCompare<LHS: Collection, RHS: Collection>(_ lhs: LHS, _ rhs: RHS) -> Bool
where LHS.Element == UInt8, RHS.Element == UInt8 {
    guard lhs.count == rhs.count else {
        return false
    }

    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}
