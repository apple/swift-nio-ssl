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
private let rootCADirectorySearchPaths = [
    "/system/etc/security/cacerts",  // Android
]

private func locateRootCADirectory() -> String? {
    return rootCADirectorySearchPaths.first(where: { FileSystemObject.pathType(path: $0) == .directory })
}
#endif
