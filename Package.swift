// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

// Used only for environment variables, does not make its way
// into the product code.
import class Foundation.ProcessInfo

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CNIOBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: abfd5ebc87ddca0fab9fca067c9d7edbc355eae8

/// This function generates the dependencies we want to express.
///
/// Importantly, it tolerates the possibility that we are being used as part
/// of the Swift toolchain, and so need to use local checkouts of our
/// dependencies.
func generateDependencies() -> [Package.Dependency] {
    if ProcessInfo.processInfo.environment["SWIFTCI_USE_LOCAL_DEPS"] == nil {
        return [
            .package(url: "https://github.com/apple/swift-nio.git", from: "2.51.0"),
            .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
        ]
    } else {
        return [
            .package(path: "../swift-nio"),
        ]
    }
}

let package = Package(
    name: "swift-nio-ssl",
    products: [
        .library(name: "NIOSSL", targets: ["NIOSSL"]),
        .executable(name: "NIOTLSServer", targets: ["NIOTLSServer"]),
        .executable(name: "NIOSSLHTTP1Client", targets: ["NIOSSLHTTP1Client"]),
/* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
        .library(name: "CNIOBoringSSL", type: .static, targets: ["CNIOBoringSSL"]),
MANGLE_END */
    ],
    dependencies: generateDependencies(),
    targets: [
        .target(name: "CNIOBoringSSL"),
        .target(
            name: "CNIOBoringSSLShims",
            dependencies: [
                "CNIOBoringSSL"
            ]),
        .target(
            name: "NIOSSL",
            dependencies: [
                "CNIOBoringSSL",
                "CNIOBoringSSLShims",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
        .executableTarget(
            name: "NIOTLSServer",
            dependencies: [
                "NIOSSL",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ],
            exclude: [
                "README.md"
            ]),
        .executableTarget(
            name: "NIOSSLHTTP1Client",
            dependencies: [
                "NIOSSL",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ],
            exclude: [
                "README.md"
            ]),
        .executableTarget(
            name: "NIOSSLPerformanceTester",
            dependencies: [
                "NIOSSL",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
        .testTarget(
            name: "NIOSSLTests",
            dependencies: [
                "NIOSSL",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
    ],
    cxxLanguageStandard: .cxx14
)
