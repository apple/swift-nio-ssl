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

add_library(CNIOBoringSSLShims STATIC
  "shims.c"
)

target_include_directories(CNIOBoringSSLShims PUBLIC
  include
  $<TARGET_PROPERTY:CNIOBoringSSL,INCLUDE_DIRECTORIES>)

target_compile_definitions(CNIOBoringSSLShims PRIVATE
  _GNU_SOURCE)

target_link_libraries(CNIOBoringSSLShims PUBLIC
  CNIOBoringSSL)

set_target_properties(CNIOBoringSSLShims PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

set_property(GLOBAL APPEND PROPERTY SWIFT_NIO_SSL_EXPORTS CNIOBoringSSLShims)
