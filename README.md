# SwiftNIO SSL

SwiftNIO SSL is a Swift package that contains an implementation of TLS based on BoringSSL. This package allows users of [SwiftNIO](https://github.com/apple/swift-nio) to write protocol clients and servers that use TLS to secure data in flight.

The name is inspired primarily by the names of the library this package uses (BoringSSL), and not because we don't know the name of the protocol. We know the protocol is TLS!

To get started, check out the [API docs](https://swiftpackageindex.com/apple/swift-nio-ssl/main/documentation/niossl).

## Using SwiftNIO SSL

SwiftNIO SSL provides two `ChannelHandler`s to use to secure a data stream: the `NIOSSLClientHandler` and the `NIOSSLServerHandler`. Each of these can be added to a `Channel` to secure the communications on that channel.

Additionally, we provide a number of low-level primitives for configuring your TLS connections. These will be shown below.

To secure a server connection, you will need a X.509 certificate chain in a file (either PEM or DER, but PEM is far easier), and the associated private key for the leaf certificate. These objects can then be wrapped up in a `TLSConfiguration` object that is used to initialize the `ChannelHandler`.

For example:

```swift
let configuration = TLSConfiguration.makeServerConfiguration(
    certificateChain: try NIOSSLCertificate.fromPEMFile("cert.pem").map { .certificate($0) },
    privateKey: .file("key.pem")
)
let sslContext = try NIOSSLContext(configuration: configuration)

let server = ServerBootstrap(group: group)
    .childChannelInitializer { channel in
        // important: The handler must be initialized _inside_ the `childChannelInitializer`
        let handler = NIOSSLServerHandler(context: sslContext)

        [...]
        channel.pipeline.addHandler(handler)
        [...]
    }
```

For clients, it is a bit simpler as there is no need to have a certificate chain or private key (though clients *may* have these things). Setup for clients may be done like this:

```swift
let configuration = TLSConfiguration.makeClientConfiguration()
let sslContext = try NIOSSLContext(configuration: configuration)

let client = ClientBootstrap(group: group)
    .channelInitializer { channel in
        // important: The handler must be initialized _inside_ the `channelInitializer`
        let handler = try NIOSSLClientHandler(context: sslContext)

        [...]
        channel.pipeline.addHandler(handler)
        [...]
    }
```

The most recent versions of SwiftNIO SSL support Swift 5.6 and newer. The minimum Swift version supported by SwiftNIO SSL releases are detailed below:

SwiftNIO SSL        | Minimum Swift Version
--------------------|----------------------
`2.0.0 ..< 2.14.0`  | 5.0
`2.14.0 ..< 2.19.0` | 5.2
`2.19.0 ..< 2.23.0` | 5.4
`2.23.0 ..< 2.23.2` | 5.5.2
`2.23.2 ...`        | 5.6
