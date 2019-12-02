//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOSSL

func run(identifier: String) {
    let serverContext = try! NIOSSLContext(configuration: .forServer(certificateChain: [.certificate(.forTesting())], privateKey: .privateKey(.forTesting())))
    let clientContext = try! NIOSSLContext(configuration: .forClient(trustRoots: .certificates([.forTesting()])))

    let dummyAddress = try! SocketAddress(ipAddress: "1.2.3.4", port: 5678)
    let backToBack = BackToBackEmbeddedChannel()
    let serverHandler = try! NIOSSLServerHandler(context: serverContext)
    let clientHandler = try! NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
    try! backToBack.client.pipeline.addHandler(clientHandler).wait()
    try! backToBack.server.pipeline.addHandler(serverHandler).wait()

    // To trigger activation of both channels we use connect().
    try! backToBack.client.connect(to: dummyAddress).wait()
    try! backToBack.server.connect(to: dummyAddress).wait()

    try! backToBack.interactInMemory()

    // Let's try 512 bytes.
    var buffer = backToBack.client.allocator.buffer(capacity: 512)
    buffer.writeBytes(repeatElement(0, count: 512))

    measure(identifier: identifier) {
        for _ in 0..<1000 {
            // A vector of 100 writes.
            for _ in 0..<100 {
                backToBack.client.write(buffer, promise: nil)
            }
            backToBack.client.flush()

            try! backToBack.interactInMemory()

            // Pull any data out of the server to avoid ballooning in memory.
            while let _ = try! backToBack.server.readInbound(as: ByteBuffer.self) { }
        }

        return 1000
    }
}
