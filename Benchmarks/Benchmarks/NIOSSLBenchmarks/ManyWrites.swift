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

import NIOCore
import NIOEmbedded
import NIOSSL

func runManyWrites(writeCount: Int) throws {
    let serverContext = try NIOSSLContext(
        configuration: .makeServerConfiguration(
            certificateChain: [.certificate(.forTesting())],
            privateKey: .privateKey(.forTesting())
        )
    )

    var clientConfig = TLSConfiguration.makeClientConfiguration()
    clientConfig.trustRoots = try .certificates([.forTesting()])
    let clientContext = try NIOSSLContext(configuration: clientConfig)

    let dummyAddress = try SocketAddress(ipAddress: "1.2.3.4", port: 5678)
    let backToBack = BackToBackEmbeddedChannel()
    let serverHandler = NIOSSLServerHandler(context: serverContext)
    let clientHandler = try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
    try backToBack.client.pipeline.addHandler(clientHandler).wait()
    try backToBack.server.pipeline.addHandler(serverHandler).wait()

    // To trigger activation of both channels we use connect().
    try backToBack.client.connect(to: dummyAddress).wait()
    try backToBack.server.connect(to: dummyAddress).wait()

    try backToBack.interactInMemory()

    // Let's try 512 bytes.
    var buffer = backToBack.client.allocator.buffer(capacity: 512)
    buffer.writeBytes(repeatElement(0, count: 512))

    for _ in 0..<writeCount {
        // A vector of 100 writes.
        for _ in 0..<100 {
            backToBack.client.write(buffer, promise: nil)
        }
        backToBack.client.flush()

        try backToBack.interactInMemory()

        // Pull any data out of the server to avoid ballooning in memory.
        while let _ = try backToBack.server.readInbound(as: ByteBuffer.self) {}
    }
}
