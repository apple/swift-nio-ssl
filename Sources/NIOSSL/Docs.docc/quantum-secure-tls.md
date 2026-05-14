# Quantum-secure TLS

Swift-nio-ssl enables quantum-secure key exchange by default. The default ``TLSConfiguration/curves`` is `[.x25519_MLKEM768, .x25519, .secp384r1]`, which offers both a post-quantum hybrid key-establishment mechanism and classical options. No configuration changes are needed to benefit from this.

If you need to customise the curve list, you can override it. For example, to support _only_ post-quantum key exchange:

```swift
tlsConfiguration.curves = [.x25519_MLKEM768]
```

To disable post-quantum key exchange and use only classical curves:

```swift
tlsConfiguration.curves = [.x25519, .secp384r1]
```