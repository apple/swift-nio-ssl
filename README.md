## Prerequisites on macOS

### Installation of the Dependencies

    brew install libressl


## TLS

Currently the source tree for SwiftNIO contains bindings for a TLS handler that links against OpenSSL/LibreSSL (more specifically, anything that provides a library called `libssl`).

This binding can cause numerous issues during the build process on different systems, depending on the environment you're in. These will usually manifest as build errors, either during the compilation stage (due to missing development headers) or during the linker stage (due to an inability to find a library to link).

If you encounter any of these errors, here are your options.

### Darwin

On Darwin systems, there is no easily-available copy of `libssl.dylib` with accompanying development headers. For this reason, we recommend installing libressl from Homebrew (`brew install libressl`).

### Linux

On Linux distributions it is almost always possible to get development headers for the system copy of libssl (e.g. via `apt-get install libssl-dev`). If you encounter problems during the compile phase, try running this command.

In some unusual situations you may encounter problems during the link phase. This is usually the result of having an extremely locked down system that does not grant you sufficient permissions to the `libssl.so` on the system.
