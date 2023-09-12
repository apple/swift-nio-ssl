//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
extension NIOSSLHandler {
    /// Configuration for a specific instance of ``NIOSSLHandler``, either client or server.
    ///
    /// This type is distinct from ``TLSConfiguration`` because it does not contain settings that
    /// apply to TLS itself. Instead, this configuration manages how the ``NIOSSLHandler`` itself
    /// operates.
    public struct Configuration: Hashable, Sendable {
        /// The maximum number of bytes we'll preserve in the outbound buffer that ``NIOSSLHandler``
        /// holds.
        ///
        /// This buffer is not typically deallocated, as it is re-used throughout the lifetime of
        /// the program. In cases where there are extremely large peak writes that are outliers in
        /// the code, the buffer may remain excessively large.
        ///
        /// Set this value to a lower value to avoid preserving too much memory. This will cause
        /// ``NIOSSLHandler`` to reallocate memory more often, which can inhibit performance, so
        /// avoid lowering this value unless you're running into trouble with memory pressure and
        /// are confident that ``NIOSSLHandler`` is at fault.
        public var maximumPreservedOutboundBufferCapacity: Int

        public init() {
            self.maximumPreservedOutboundBufferCapacity = .max
        }
    }
}
