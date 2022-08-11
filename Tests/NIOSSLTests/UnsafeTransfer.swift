//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// ``UnsafeMutableTransferBox`` can be used to make non-`Sendable` values `Sendable` and mutable.
/// It can be used to capture local mutable values in a `@Sendable` closure and mutate them from within the closure.
/// As the name implies, the usage of this is unsafe because it disables the sendable checking of the compiler and does not add any synchronisation.
@usableFromInline
final class UnsafeMutableTransferBox<Wrapped> {
    @usableFromInline
    var wrappedValue: Wrapped
    
    @inlinable
    init(_ wrappedValue: Wrapped) {
        self.wrappedValue = wrappedValue
    }
}
#if swift(>=5.5) && canImport(_Concurrency)
extension UnsafeMutableTransferBox: @unchecked Sendable {}
#endif
