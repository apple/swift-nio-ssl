// swift-tools-version:5.8
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
// BoringSSL Commit: 3309ca66385ecb0c37f1ac1be9f88712e25aa8ec

/// This function generates the dependencies we want to express.
///
/// Importantly, it tolerates the possibility that we are being used as part
/// of the Swift toolchain, and so need to use local checkouts of our
/// dependencies.
func generateDependencies() -> [Package.Dependency] {
    if ProcessInfo.processInfo.environment["SWIFTCI_USE_LOCAL_DEPS"] == nil {
        return [
            .package(url: "https://github.com/apple/swift-nio.git", from: "2.54.0"),
            .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
        ]
    } else {
        return [
            .package(path: "../swift-nio"),
        ]
    }
}

// This doesn't work when cross-compiling: the privacy manifest will be included in the Bundle and
// Foundation will be linked. This is, however, strictly better than unconditionally adding the
// resource.
#if canImport(Darwin)
let includePrivacyManifest = true
#else
let includePrivacyManifest = false
#endif

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
        .target(
            name: "CNIOBoringSSL",
            cSettings: [
              .define("_GNU_SOURCE"),
              .define("_POSIX_C_SOURCE", to: "200112L"),
              .define("_DARWIN_C_SOURCE")
            ]),
        .target(
            name: "CNIOBoringSSLShims",
            dependencies: [
                "CNIOBoringSSL"
            ],
            cSettings: [
              .define("_GNU_SOURCE"),
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
            ],
            resources: includePrivacyManifest ? [.copy("ProcessInfo.xcprivacy")] : []
        ),
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
