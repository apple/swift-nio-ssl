##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftNIO open source project
##
## Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftNIO project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(NIOSSL
  "AndroidCABundle.swift"
  "ByteBufferBIO.swift"
  "CustomPrivateKey.swift"
  "FreeBSDCABundle.swift"
  "IdentityVerification.swift"
  "LinuxCABundle.swift"
  "NIOSSLClientHandler.swift"
  "NIOSSLHandler+Configuration.swift"
  "NIOSSLHandler.swift"
  "NIOSSLServerHandler.swift"
  "ObjectIdentifier.swift"
  "PosixPort.swift"
  "SSLCallbacks.swift"
  "SSLCertificate.swift"
  "SSLCertificateExtensions.swift"
  "SSLCertificateName.swift"
  "SSLConnection.swift"
  "SSLContext.swift"
  "SSLErrors.swift"
  "SSLInit.swift"
  "SSLPKCS12Bundle.swift"
  "SSLPrivateKey.swift"
  "SSLPublicKey.swift"
  "SecurityFrameworkCertificateVerification.swift"
  "String+unsafeUninitializedCapacity.swift"
  "SubjectAlternativeName.swift"
  "SwiftCrypto/NIOSSLSecureBytes.swift"
  "SwiftCrypto/RNG.swift"
  "SwiftCrypto/SafeCompare.swift"
  "SwiftCrypto/Zeroization.swift"
  "TLSConfiguration.swift"
  "UniversalBootstrapSupport.swift"
  "UnsafeKeyAndChainTarget.swift"
)

target_include_directories(NIOSSL PRIVATE
  $<TARGET_PROPERTY:CNIOBoringSSL,INCLUDE_DIRECTORIES>
  $<TARGET_PROPERTY:CNIOBoringSSLShims,INCLUDE_DIRECTORIES>)
target_link_libraries(NIOSSL PUBLIC
  CNIOBoringSSL
  CNIOBoringSSLShims
  CNIOLinux
  NIO
  NIOConcurrencyHelpers
  NIOCore
  NIOTLS)

target_compile_options(NIOSSL PRIVATE ${SWIFT_NIO_SSL_COMPILE_OPTIONS})
set_target_properties(NIOSSL PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

swift_nio_ssl_install_target(NIOSSL)
set_property(GLOBAL APPEND PROPERTY SWIFT_NIO_SSL_EXPORTS NIOSSL)
