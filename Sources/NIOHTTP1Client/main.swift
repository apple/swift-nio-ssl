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

import NIO
import NIOFoundationCompat
import NIOHTTP1
import NIOSSL
import Foundation

private final class HTTPResponseHandler: ChannelInboundHandler {

    let promise: EventLoopPromise<Void>

    var closeFuture: EventLoopFuture<Void>? = nil

    init(_ promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    typealias InboundIn = HTTPClientResponsePart

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let httpResponsePart = unwrapInboundIn(data)
        switch httpResponsePart {
        case .head(let httpResponseHeader):
            print("\(httpResponseHeader.version) \(httpResponseHeader.status.code) \(httpResponseHeader.status.reasonPhrase)")
            for (name, value) in httpResponseHeader.headers {
                print("\(name): \(value)")
            }
        case .body(var byteBuffer):
            if let data = byteBuffer.readData(length: byteBuffer.readableBytes) {
                FileHandle.standardOutput.write(data)
            }
        case .end(_):
            closeFuture = context.channel.close()
            promise.succeed(())
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if closeFuture == nil {
            closeFuture = context.channel.close()
            promise.fail(ChannelError.inputClosed)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("Error: ", error)
        closeFuture = context.channel.close()
        promise.succeed(())
    }
}

let arguments = CommandLine.arguments
let arg1 = arguments.dropFirst().first

var url: URL

if let u = arg1 {
    url = URL(string: u)!
} else {
    url = URL(string: "https://::1:4433/get")!
}

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let promise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise(of: Void.self)
defer {
    try! promise.futureResult.wait()
    try! eventLoopGroup.syncShutdownGracefully()
}

let tlsConfiguration = TLSConfiguration.forClient()
let sslContext = try! NIOSSLContext(configuration: tlsConfiguration)

let bootstrap = ClientBootstrap(group: eventLoopGroup)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelInitializer { channel in
            let openSslHandler = try! NIOSSLClientHandler(context: sslContext, serverHostname: url.host)
            return channel.pipeline.addHandler(openSslHandler).flatMap {
                channel.pipeline.addHTTPClientHandlers()
            }.flatMap {
                channel.pipeline.addHandler(HTTPResponseHandler(promise))
            }
        }

func sendRequest(_ channel: Channel) -> EventLoopFuture<Void> {
    var request = HTTPRequestHead(version: HTTPVersion(major: 1, minor: 1), method: HTTPMethod.GET, uri: url.absoluteString)
    request.headers = HTTPHeaders([
        ("Host", url.host!),
        ("User-Agent", "swift-nio"),
        ("Accept", "application/json"),
        ("Connection", "close")
    ])
    channel.write(HTTPClientRequestPart.head(request), promise: nil)
    return channel.writeAndFlush(HTTPClientRequestPart.end(nil))
}

bootstrap.connect(host: url.host!, port: url.port ?? 443)
        .flatMap { sendRequest($0) }
        .cascadeFailure(to: promise)
