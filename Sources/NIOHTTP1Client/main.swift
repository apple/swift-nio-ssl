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
import NIOHTTP1
import NIOOpenSSL

private final class HTTPResponseHandler: ChannelInboundHandler {

    let promise: EventLoopPromise<Void>

    init(_ promise: EventLoopPromise<Void>) {
        self.promise = promise
    }

    typealias InboundIn = HTTPClientResponsePart

    func channelRead(ctx: ChannelHandlerContext, data: NIOAny) {
        let httpResponsePart = unwrapInboundIn(data)
        switch httpResponsePart {
        case .head(let httpResponseHeader):
            print("\(httpResponseHeader.version) \(httpResponseHeader.status.code) \(httpResponseHeader.status.reasonPhrase)")
            for (name, value) in httpResponseHeader.headers {
                print("\(name): \(value)")
            }
        case .body(var byteBuffer):
            if let responseBody = byteBuffer.readString(length: byteBuffer.readableBytes) {
                print(responseBody)
            }
        case .end(_):
            break
        }
    }

    func channelReadComplete(ctx: ChannelHandlerContext) {
        _ = ctx.channel.close()
        promise.succeed(result: ())
    }

    func errorCaught(ctx: ChannelHandlerContext, error: Error) {
        print("Error: ", error)
        _ = ctx.channel.close()
        promise.succeed(result: ())
    }
}

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
let promise: EventLoopPromise<Void> = eventLoopGroup.next().newPromise()
defer {
    try! promise.futureResult.wait()
    try! eventLoopGroup.syncShutdownGracefully()
}

let tlsConfiguration = TLSConfiguration.forClient()
let sslContext = try! SSLContext(configuration: tlsConfiguration)
let openSslHandler = try! OpenSSLClientHandler(context: sslContext, serverHostname: "httpbin.org")

let bootstrap = ClientBootstrap(group: eventLoopGroup)
        .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .channelInitializer { channel in
            _ = channel.pipeline.add(handler: openSslHandler)
            _ = channel.pipeline.addHTTPClientHandlers()
            return channel.pipeline.add(handler: HTTPResponseHandler(promise))
        }

func sendRequest(_ channel: Channel) {
    var request = HTTPRequestHead(version: HTTPVersion(major: 1, minor: 1), method: HTTPMethod.GET, uri: "https://httpbin.org/get?query=param")
    request.headers = HTTPHeaders([
        ("Host", "httpbin.org"),
        ("User-Agent", "swift-nio"),
        ("Accept", "application/json")
    ])
    _ = channel.write(HTTPClientRequestPart.head(request))
    _ = channel.writeAndFlush(HTTPClientRequestPart.end(nil))
}

bootstrap.connect(host: "httpbin.org", port: 443)
        .whenSuccess { sendRequest($0) }
