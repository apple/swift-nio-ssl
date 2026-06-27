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

#if os(FreeBSD)
/// The path to the root CA bundle file.
///
/// May be nil if we could not find the root CA bundle file.
internal let rootCAFilePath: String? = locateRootCAFile()

/// The path to the root CA bundle directory.
///
/// May be nil if we could not find the root CA bundle directory.
internal let rootCADirectoryPath: String? = locateRootCADirectory()

/// This is a list of root CA file search paths.
///
/// FreeBSD ships the trust store via the security/ca_root_nss port, and the base system carries a
/// bundle at /etc/ssl/cert.pem (14+). If you are aware of another location, please open a pull request.
private let rootCAFileSearchPaths = [
    "/usr/local/etc/ssl/cert.pem",  // openssl / ca_root_nss (LibreSSL-style default)
    "/etc/ssl/cert.pem",  // base system (14+)
    "/usr/local/share/certs/ca-root-nss.crt",  // ca_root_nss port bundle
]

/// This is a list of root CA directory search paths.
private let rootCADirectorySearchPaths = [
    "/usr/local/share/certs"  // ca_root_nss port
]

private func locateRootCAFile() -> String? {
    rootCAFileSearchPaths.first(where: { FileSystemObject.pathType(path: $0) == .file })
}

private func locateRootCADirectory() -> String? {
    rootCADirectorySearchPaths.first(where: { FileSystemObject.pathType(path: $0) == .directory })
}
#endif
