#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu

sourcedir=$(pwd)
workingdir=$(mktemp -d)
projectname=$(basename $workingdir)

cd $workingdir
swift package init

cat << EOF > Package.swift
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "interop",
    products: [
        .library(
            name: "interop",
            targets: ["interop"]
        ),
    ],
    dependencies: [
        .package(path: "$sourcedir")
    ],
    targets: [
        .target(
            name: "interop",
            // Depend on all products of swift-nio-ssl to make sure they're all
            // compatible with cxx interop.
            dependencies: [
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTLSServer", package: "swift-nio-ssl"),
                .product(name: "NIOSSLHTTP1Client", package: "swift-nio-ssl")
            ],
            swiftSettings: [.interoperabilityMode(.Cxx)]
        )
    ]
)
EOF

cat << EOF > Sources/$projectname/$(echo $projectname | tr . _).swift
import NIOSSL
import NIOTLSServer
import NIOSSLHTTP1Client
EOF

swift build
