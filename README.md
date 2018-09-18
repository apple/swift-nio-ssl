# SwiftNIO SSL

SwiftNIO SSL is a Swift package that contains an implementation of TLS based on OpenSSL-compatible libraries (that is, any library that ships a libssl that is compatible with OpenSSL's). This package allows users of [SwiftNIO](https://github.com/apple/swift-nio) to write protocol clients and servers that use TLS to secure data in flight.

The name is inspired primarily by the names of the libraries this package supports (e.g. OpenSSL, LibreSSL, and friends), and not because we don't know the name of the protocol. We know the protocol is TLS!

## Using SwiftNIO SSL

SwiftNIO SSL provides two `ChannelHandler`s to use to secure a data stream: the `OpenSSLClientHandler` and the `OpenSSLServerHandler`. Each of these can be added to a `Channel` to secure the communications on that channel.

Additionally, we provide a number of low-level primitives for configuring your TLS connections. These will be shown below.

To secure a server connection, you will need a X.509 certificate chain in a file (either PEM or DER, but PEM is far easier), and the associated private key for the leaf certificate. These objects can then be wrapped up in a `TLSConfiguration` object that is used to initialize the `ChannelHandler`.

For example:

```swift
let configuration = TLSConfiguration.forServer(certificateChain: [.file("cert.pem")], privateKey: .file("key.pem")) 
let sslContext = try SSLContext(configuration: configuration)
let handler = try OpenSSLServerHandler(context: sslContext)
// Add the created handler to the pipeline.
```

For clients, it is a bit simpler as there is no need to have a certificate chain or private key (though clients *may* have these things). Setup for clients may be done like this:

```swift
let configuration = TLSConfiguration.forClient()
let sslContext = try SSLContext(configuration: configuration)
let handler = try OpenSSLClientHandler(context: sslContext)
// Add the created handler to the pipeline.
```

## Installation

This binding can cause numerous issues during the build process on different systems, depending on the environment you're in. These will usually manifest as build errors, either during the compilation stage (due to missing development headers) or during the linker stage (due to an inability to find a library to link).

If you encounter any of these errors, here are your options.

### Darwin (iOS, macOS, tvOS, ...)

If you target iOS/tv 12+ or macOS 10.14+ we recommend using [`swift-nio-transport-services`](https://github.com/apple/swift-nio-transport-services) which
is SwiftNIO on top of [`Network.framework`](https://developer.apple.com/documentation/network) which supports TLS out of the box.

If you need to target older versions on macOS we recommend installing libressl from Homebrew (`brew install libressl`) as there is no easily-available copy of
`libssl.dylib` with accompanying development headers.


### Linux

On Linux distributions it is almost always possible to get development headers for the system copy of libssl (e.g. via `apt-get install libssl-dev`). If you encounter problems during the compile phase, try running this command.

In some unusual situations you may encounter problems during the link phase. This is usually the result of having an extremely locked down system that does not grant you sufficient permissions to the `libssl.so` on the system.
