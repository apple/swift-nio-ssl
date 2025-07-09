# Trust Roots and Certificate Validation Behavior

Understanding how ``TLSConfiguration/trustRoots`` and ``TLSConfiguration/additionalTrustRoots`` affect certificate validation across different platforms.

## Overview

SwiftNIO SSL provides two properties in ``TLSConfiguration`` for configuring certificate validation: ``TLSConfiguration/trustRoots`` and ``TLSConfiguration/additionalTrustRoots``. The behavior of these properties differs significantly between Apple platforms and other platforms, which can lead to unexpected certificate validation failures.

This article explains the behavioral matrix and helps you choose the right configuration for your use case.

## Certificate Validation Backends

SwiftNIO SSL uses different certificate validation backends depending on your configuration:

- **SecTrust** (Apple platforms only): The system's native certificate validator, which is stricter and follows Apple's certificate validation policies
- **BoringSSL**: The embedded certificate validator, which is more permissive and consistent across platforms

## Behavioral Matrix

The choice of validation backend depends on your ``TLSConfiguration/trustRoots`` and ``TLSConfiguration/additionalTrustRoots`` settings:

| Configuration | Apple Platforms | Other Platforms |
|---------------|-----------------|-----------------|
| `trustRoots = .default`, no additional trust roots | SecTrust with default settings | BoringSSL with system PEM files |
| `trustRoots = nil`, no additional trust roots | SecTrust with default settings | BoringSSL with system PEM files |
| `trustRoots = .file(_)`, no additional trust roots | BoringSSL with specified file | BoringSSL with specified file |
| `trustRoots = .certificates(_)`, no additional trust roots | BoringSSL with specified certificates | BoringSSL with specified certificates |
| `trustRoots = .default`, additional trust roots provided | SecTrust with additional roots via `SecTrustSetAnchorCertificates` | BoringSSL with system PEM files and additional roots |
| `trustRoots = nil`, additional trust roots provided | SecTrust with additional roots via `SecTrustSetAnchorCertificates` | BoringSSL with system PEM files and additional roots |
| `trustRoots = .file(_)`, additional trust roots provided | BoringSSL with specified file and additional roots | BoringSSL with specified file and additional roots |
| `trustRoots = .certificates(_)`, additional trust roots provided | BoringSSL with specified certificates and additional roots | BoringSSL with specified certificates and additional roots |

## Key Behavioral Differences

**SecTrust:**
- Used when `trustRoots` is `.default` or `nil` on Apple platforms
- Enforces stricter certificate chain validation rules
- May reject certificate chains that BoringSSL accepts
- Behaves the same way that Safari and most other browsers do

**BoringSSL:**
- Used in all other cases, including on Apple platforms when `trustRoots` is `.file(_)` or `.certificates(_)`
- More lenient about certificate formatting and extensions
- Consistent behavior across all platforms

## Debugging Certificate Issues

When certificate validation fails, check the system logs for detailed error messages:

```bash
# macOS/iOS system logs often contain detailed certificate validation errors
log show --predicate 'subsystem == "com.apple.security"' --last 1m
```

The error messages will help you understand whether the issue is with certificate formatting, missing extensions, or chain validation problems.

## Topics

### Related Configuration

- ``TLSConfiguration/trustRoots``
- ``TLSConfiguration/additionalTrustRoots``
- ``TLSConfiguration/certificateVerification``
- ``NIOSSLTrustRoots``
- ``NIOSSLAdditionalTrustRoots``