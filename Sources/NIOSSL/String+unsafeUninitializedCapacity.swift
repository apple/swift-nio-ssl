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
    /// This is a backport of a proposed String initializer that will allow writing directly into an uninitialized String's backing memory.
    /// This feature will be useful when decoding Huffman-encoded HPACK strings.
    ///
    /// As this API does not exist prior to 5.3 on Linux, or on older Apple platforms, we fake it out with a pointer and accept the extra copy.
    init(backportUnsafeUninitializedCapacity capacity: Int,
         initializingUTF8With initializer: (_ buffer: UnsafeMutableBufferPointer<UInt8>) throws -> Int) rethrows {
        let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: capacity)
        defer {
            buffer.deallocate()
        }


        let initializedCount = try initializer(buffer)
        precondition(initializedCount <= capacity, "Overran buffer in initializer!")

        self = String(decoding: UnsafeMutableBufferPointer(start: buffer.baseAddress!, count: initializedCount), as: UTF8.self)
    }
}

// Frustratingly, Swift 5.3 shipped before the macOS 11 SDK did, so we cannot gate the availability of
// this declaration on having the 5.3 compiler. This has caused a number of build issues. While updating
// to newer Xcodes does work, we can save ourselves some hassle and just wait until 5.4 to get this
// enhancement on Apple platforms.
#if (compiler(>=5.3) && !(os(macOS) || os(iOS) || os(tvOS) || os(watchOS))) || compiler(>=5.4)
extension String {
    init(customUnsafeUninitializedCapacity capacity: Int,
         initializingUTF8With initializer: (_ buffer: UnsafeMutableBufferPointer<UInt8>) throws -> Int) rethrows {
        if #available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *) {
            try self.init(unsafeUninitializedCapacity: capacity, initializingUTF8With: initializer)
        } else {
            try self.init(backportUnsafeUninitializedCapacity: capacity, initializingUTF8With: initializer)
        }
    }
}
#else
extension String {
    init(customUnsafeUninitializedCapacity capacity: Int,
         initializingUTF8With initializer: (_ buffer: UnsafeMutableBufferPointer<UInt8>) throws -> Int) rethrows {
        try self.init(backportUnsafeUninitializedCapacity: capacity, initializingUTF8With: initializer)
    }
}
#endif
