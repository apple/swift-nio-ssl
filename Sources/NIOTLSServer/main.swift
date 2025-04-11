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

import NIOCore
import NIOPosix
import NIOSSL

import struct Foundation.URL

private final class EchoHandler: ChannelInboundHandler {
    public typealias InboundIn = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.write(data, promise: nil)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }
}

let certificateChain = try NIOSSLCertificate.fromPEMFile("cert.pem")
let privateKey = try! NIOSSLPrivateKey(file: "key.pem", format: .pem)
let sslContext = try! NIOSSLContext(
    configuration: TLSConfiguration.makeServerConfiguration(
        certificateChain: certificateChain.map { .certificate($0) },
        privateKey: .privateKey(privateKey)
    )
)

let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let bootstrap = ServerBootstrap(group: group)
    // Specify backlog and enable SO_REUSEADDR for the server itself
    .serverChannelOption(ChannelOptions.backlog, value: 256)
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)

    // Set the handlers that are applied to the accepted channels.
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.addHandlers(NIOSSLServerHandler(context: sslContext), EchoHandler())
        }
    }

    // Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
    .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
    .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)

defer {
    try! group.syncShutdownGracefully()
}

// First argument is the program path
let arguments = CommandLine.arguments
let arg1 = arguments.dropFirst().first
let arg2 = arguments.dropFirst().dropFirst().first

var host: String = "::1"
var port: Int = 4433
switch (arg1, arg1.flatMap { Int($0) }, arg2.flatMap { Int($0) }) {
case (.some(let h), _, .some(let p)):
    // we got two arguments, let's interpret that as host and port
    host = h
    port = p
case (_, .some(let p), _):
    // only one argument --> port
    port = p
default:
    ()
}

let channel = try bootstrap.bind(host: host, port: port).wait()

print("Server started and listening on \(channel.localAddress!)")

// This will never unblock as we don't close the ServerChannel
try channel.closeFuture.wait()

print("Server closed")
