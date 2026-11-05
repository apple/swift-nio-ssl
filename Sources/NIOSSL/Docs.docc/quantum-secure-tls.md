# Quantum-secure TLS

Swift-nio-ssl enables quantum-secure key exchange by default. The default ``TLSConfiguration/curves`` is `[.x25519_MLKEM768, .x25519, .secp256r1, .secp384r1]`, which offers both a post-quantum hybrid key-establishment mechanism and classical options. No configuration changes are needed to benefit from this.

If you need to customise the curve list, you can override it. For example, to support _only_ post-quantum key exchange:

```swift
tlsConfiguration.curves = [.x25519_MLKEM768]
```

To disable post-quantum key exchange and use only classical curves:

```swift
tlsConfiguration.curves = [.x25519, .secp256r1, .secp384r1]
```

## Post-quantum signatures

Swift-nio-ssl signs the TLS 1.3 handshake with ML-DSA when the configured private key is an ML-DSA key, and the default ``TLSConfiguration/verifySignatureAlgorithms`` accepts ML-DSA signatures from peers alongside the classical algorithms. No configuration changes are needed to benefit from this.

To stop accepting ML-DSA signatures and use only classical algorithms:

```swift
tlsConfiguration.verifySignatureAlgorithms = [
    .ecdsaSecp256R1Sha256, .ecdsaSecp384R1Sha384,
    .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512,
]
```

Setting this property replaces the built-in list, so include every classical algorithm your peers still need.
