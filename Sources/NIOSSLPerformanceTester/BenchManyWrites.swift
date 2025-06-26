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

final class BenchManyWrites: Benchmark {
    let clientContext: NIOSSLContext
    let serverContext: NIOSSLContext
    let dummyAddress: SocketAddress
    let backToBack: BackToBackEmbeddedChannel
    let loopCount: Int
    let writeSize: Int
    var buffer: ByteBuffer?

    init(loopCount: Int, writeSizeInBytes writeSize: Int) throws {
        self.loopCount = loopCount
        self.writeSize = writeSize
        self.serverContext = try NIOSSLContext(
            configuration: .makeServerConfiguration(
                certificateChain: [.certificate(.forTesting())],
                privateKey: .privateKey(.forTesting())
            )
        )

        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.trustRoots = try .certificates([.forTesting()])
        self.clientContext = try NIOSSLContext(configuration: clientConfig)

        self.dummyAddress = try SocketAddress(ipAddress: "1.2.3.4", port: 5678)
        self.backToBack = BackToBackEmbeddedChannel()
    }

    func setUp() throws {
        let serverHandler = NIOSSLServerHandler(context: self.serverContext)
        let clientHandler = try NIOSSLClientHandler(context: self.clientContext, serverHostname: "localhost")
        try self.backToBack.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.backToBack.server.pipeline.syncOperations.addHandler(serverHandler)

        // To trigger activation of both channels we use connect().
        try self.backToBack.client.connect(to: dummyAddress).wait()
        try self.backToBack.server.connect(to: dummyAddress).wait()
        try self.backToBack.interactInMemory()

        self.buffer = self.backToBack.client.allocator.buffer(capacity: self.writeSize)
        self.buffer!.writeBytes(repeatElement(0, count: self.writeSize))

    }

    func tearDown() {}

    func run() throws -> Int {
        guard let buffer = self.buffer else {
            fatalError("Couldn't get buffer")
        }

        for _ in 0..<self.loopCount {
            // A vector of 100 writes.
            for _ in 0..<100 {
                self.backToBack.client.write(buffer, promise: nil)
            }
            self.backToBack.client.flush()

            try self.backToBack.interactInMemory()

            // Pull any data out of the server to avoid ballooning in memory.
            while let _ = try self.backToBack.server.readInbound(as: ByteBuffer.self) {}
        }

        return self.loopCount
    }
}
