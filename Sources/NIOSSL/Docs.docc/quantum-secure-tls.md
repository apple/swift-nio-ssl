# Quantum-secure TLS

To enable quantum-secure algorithms in swift-nio-ssl requires minimal configuration changes. While the algorithms are being standardised they are off by default, but once the code points are final we will be enabling them by default.

In the meantime, if you wish to add support, you can enable ``NIOTLSCurve/x25519_MLKEM768`` with the following change:

```swift
tlsConfiguration.curves = [.x25519_MLKEM768, .x25519, .secp384r1]
```

This configuration offers both a post-quantum hybrid key-establishment mechanism, as well as classical options. This is an appropriate choice for general-purpose use as it can support older clients, but it may not be appropriate for your use-case. If you are aiming to support _only_ post-quantum key exchange, you can do so by setting only PQ or hybrid KEMs:

```swift
tlsConfiguration.curves = [.x25519_MLKEM768]
```