// swift-tools-version:5.0
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

let package = Package(
    name: "swift-nio-ssl",
    products: [
        .library(name: "NIOSSL", targets: ["NIOSSL"]),
        .executable(name: "NIOTLSServer", targets: ["NIOTLSServer"]),
        .library(name: "CNIOBoringSSL", type: .static, targets: ["CNIOBoringSSL"]),
        .executable(name: "NIOHTTP1Client", targets: ["NIOHTTP1Client"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", .branch("master")),
    ],
    targets: [
        .target(name: "CNIOBoringSSL"),
        .target(name: "CNIOBoringSSLShims", dependencies: ["CNIOBoringSSL"]),
        .target(name: "NIOSSL",
                dependencies: ["NIO", "NIOConcurrencyHelpers", "CNIOBoringSSL", "CNIOBoringSSLShims", "NIOTLS", "_NIO1APIShims"]),
        .target(name: "NIOTLSServer", dependencies: ["NIO", "NIOSSL", "NIOConcurrencyHelpers"]),
        .target(name: "NIOHTTP1Client", dependencies: ["NIO", "NIOHTTP1", "NIOSSL"]),
        .testTarget(name: "NIOSSLTests", dependencies: ["NIOTLS", "NIOSSL"]),
    ],
    cxxLanguageStandard: .cxx11
)
