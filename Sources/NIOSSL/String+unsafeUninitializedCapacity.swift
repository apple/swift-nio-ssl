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

extension String {
    /// This is a backport of `String.init(unsafeUninitializedCapacity:initializingUTF8With:)`
    /// that allows writing directly into an uninitialized String's backing memory.
    ///
    /// As this API does not exist on older Apple platforms, we fake it out with a pointer and accept the extra copy.
    init(
        customUnsafeUninitializedCapacity capacity: Int,
        initializingUTF8With initializer: (_ buffer: UnsafeMutableBufferPointer<UInt8>) throws -> Int
    ) rethrows {
        if #available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *) {
            try self.init(unsafeUninitializedCapacity: capacity, initializingUTF8With: initializer)
        } else {
            try self.init(backportUnsafeUninitializedCapacity: capacity, initializingUTF8With: initializer)
        }
    }
    
    private init(
        backportUnsafeUninitializedCapacity capacity: Int,
        initializingUTF8With initializer: (_ buffer: UnsafeMutableBufferPointer<UInt8>) throws -> Int
    ) rethrows {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: capacity)
        defer {
            buffer.deallocate()
        }


        let initializedCount = try initializer(buffer)
        precondition(initializedCount <= capacity, "Overran buffer in initializer!")

        self = String(decoding: UnsafeMutableBufferPointer(start: buffer.baseAddress!, count: initializedCount), as: UTF8.self)
    }
}
