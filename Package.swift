// swift-tools-version:5.2
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CNIOBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: ab7811ee8751ea699b22095caa70246f641ed3a2

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
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.19.0"),
    ],
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
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
        .target(
            name: "NIOTLSServer",
            dependencies: [
                "NIOSSL",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ]),
        .target(
            name: "NIOSSLHTTP1Client",
            dependencies: [
                "NIOSSL",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]),
        .target(
            name: "NIOSSLPerformanceTester",
            dependencies: [
                "NIOSSL",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
        .testTarget(
            name: "NIOSSLTests",
            dependencies: [
                "NIOSSL",
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
    ],
    cxxLanguageStandard: .cxx14
)
