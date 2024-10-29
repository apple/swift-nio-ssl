//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(Android)
/// The path to the root CA bundle directory.
///
/// May be nil if we could not find the root CA bundle directory.
internal let rootCADirectoryPath: String? = locateRootCADirectory()

/// This is a list of root CA directory search paths.
///
/// This list contains paths as validated against several distributions. If you are aware of a CA bundle on a specific distribution
/// that is not present here, please open a pull request that adds the appropriate search path.
/// Some distributions do not ship CA directories: as such, it is not a problem if a distribution that is present in rootCAFileSearchPaths
/// is not present in this list.
//see https://android.googlesource.com/platform/frameworks/base/+/8b192b19f264a8829eac2cfaf0b73f6fc188d933%5E%21/#F0
private let rootCADirectorySearchPaths = [
    "/apex/com.android.conscrypt/cacerts",  // >= Android14
    "/system/etc/security/cacerts",  // < Android14
]

private func locateRootCADirectory() -> String? {
    rootCADirectorySearchPaths.first(where: { FileSystemObject.pathType(path: $0) == .directory })
}
#endif
