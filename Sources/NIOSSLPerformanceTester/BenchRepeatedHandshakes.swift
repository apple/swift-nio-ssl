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

final class BenchRepeatedHandshakes: Benchmark {
    let clientContext: NIOSSLContext
    let serverContext: NIOSSLContext
    let dummyAddress: SocketAddress
    let loopCount: Int

    init(loopCount: Int) throws {
        self.loopCount = loopCount
        self.serverContext = try NIOSSLContext(configuration: .forServer(certificateChain: [.certificate(.forTesting())], privateKey: .privateKey(.forTesting())))
        self.clientContext = try NIOSSLContext(configuration: .forClient(trustRoots: .certificates([.forTesting()])))
        self.dummyAddress = try SocketAddress(ipAddress: "1.2.3.4", port: 5678)
    }

    func setUp() { }

    func tearDown() { }

    func run() throws -> Int {
        for _ in 0..<self.loopCount {
            let backToBack = BackToBackEmbeddedChannel()
            let serverHandler = try NIOSSLServerHandler(context: self.serverContext)
            let clientHandler = try NIOSSLClientHandler(context: self.clientContext, serverHostname: "localhost")
            try backToBack.client.pipeline.addHandler(clientHandler).wait()
            try backToBack.server.pipeline.addHandler(serverHandler).wait()

            // To trigger activation of both channels we use connect().
            try backToBack.client.connect(to: self.dummyAddress).wait()
            try backToBack.server.connect(to: self.dummyAddress).wait()

            try backToBack.interactInMemory()

            // Ok, now do shutdown.
            backToBack.client.close(promise: nil)
            try backToBack.interactInMemory()
            try backToBack.client.closeFuture.wait()
            try backToBack.server.closeFuture.wait()
         }

        return self.loopCount
    }
}
