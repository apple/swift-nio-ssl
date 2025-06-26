# ``TLSConfiguration``

## Topics

### Creating a TLS configuration

- ``clientDefault``
- ``makeClientConfiguration()``
- ``makeServerConfiguration(certificateChain:privateKey:)``
- ``makePreSharedKeyConfiguration()``

### Inspecting a configuration

- ``minimumTLSVersion``
- ``maximumTLSVersion``
- ``certificateVerification``
- ``trustRoots``
- ``certificateChain``
- ``privateKey``
- ``applicationProtocols``
- ``shutdownTimeout``
- ``keyLogCallback``
- ``renegotiationSupport``
- ``sslContextCallback``

### Inspecting configuration ciphers

- ``cipherSuites``
- ``verifySignatureAlgorithms``
- ``signingSignatureAlgorithms``
- ``cipherSuiteValues``
- ``curves``
- ``additionalTrustRoots``
- ``sendCANameList``

### Inspecting pre-shared key configurations

- ``pskClientProvider``
- ``pskHint``
- ``pskServerProvider``
- ``pskClientCallback``
- ``pskServerCallback``

### Comparing and Hashing TLS configurations

- ``bestEffortEquals(_:)``
- ``bestEffortHash(into:)``

### Deprecated initializers

- ``forClient(cipherSuites:minimumTLSVersion:maximumTLSVersion:certificateVerification:trustRoots:certificateChain:privateKey:applicationProtocols:shutdownTimeout:keyLogCallback:)``
- ``forClient(cipherSuites:minimumTLSVersion:maximumTLSVersion:certificateVerification:trustRoots:certificateChain:privateKey:applicationProtocols:shutdownTimeout:keyLogCallback:renegotiationSupport:)``
- ``forClient(cipherSuites:verifySignatureAlgorithms:signingSignatureAlgorithms:minimumTLSVersion:maximumTLSVersion:certificateVerification:trustRoots:certificateChain:privateKey:applicationProtocols:shutdownTimeout:keyLogCallback:renegotiationSupport:)``

- ``forServer(certificateChain:privateKey:cipherSuites:minimumTLSVersion:maximumTLSVersion:certificateVerification:trustRoots:applicationProtocols:shutdownTimeout:keyLogCallback:)``
- ``forServer(certificateChain:privateKey:cipherSuites:verifySignatureAlgorithms:signingSignatureAlgorithms:minimumTLSVersion:maximumTLSVersion:certificateVerification:trustRoots:applicationProtocols:shutdownTimeout:keyLogCallback:)``
