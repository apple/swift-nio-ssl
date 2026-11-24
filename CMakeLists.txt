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

cmake_minimum_required(VERSION 3.29)

project(SwiftNIOSSL
  LANGUAGES ASM C CXX Swift)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

include(SwiftNIOSSLSupport)

option(BUILD_SHARED_LIBS "Build shared libraries by default" YES)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_Swift_MODULE_DIRECTORY ${CMAKE_BINARY_DIR}/swift)

set(SWIFT_NIO_SSL_COMPILE_OPTIONS
    -package-name swift-nio-ssl
    -enable-upcoming-feature MemberImportVisibility
)

set(CMAKE_POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS})

if(CMAKE_SYSTEM_NAME STREQUAL Darwin AND NOT CMAKE_CROSSCOMPILING)
  set(CMAKE_AR "/usr/bin/ar")
  set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> crs <TARGET> <LINK_FLAGS> <OBJECTS>")
  set(CMAKE_RANLIB "/usr/bin/ranlib")
endif()

set(CMAKE_CXX_STANDARD 17)
if(CMAKE_SYSTEM_NAME STREQUAL Windows)
  # We can only link against the DLL version of the MSVC runtime library for now.
  set(CMAKE_Swift_COMPILE_OPTIONS_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)
  if(CMAKE_Swift_COMPILER_VERSION VERSION_EQUAL 0.0.0 OR CMAKE_Swift_COMPILER_VERSION VERSION_GREATER_EQUAL 6.2)
    # We need to set the static library prefix to "lib" so that we can link against the static libraries.
    set(CMAKE_STATIC_LIBRARY_PREFIX_Swift "lib")
  endif()
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL Darwin)
  find_package(dispatch CONFIG)
  find_package(Foundation CONFIG)
endif()

include(FetchContent)

set(_NIO_SSL_SAVED_BUILD_EXAMPLES ${BUILD_EXAMPLES})
set(_NIO_SSL_SAVED_BUILD_TESTING ${BUILD_TESTING})

find_package(SwiftNIO CONFIG)
if(NOT SwiftNIO_FOUND)
  message("-- Vending swift-nio")
  FetchContent_Declare(SwiftNIO
    GIT_REPOSITORY https://github.com/apple/swift-nio
    GIT_TAG 2.105.2)
  FetchContent_MakeAvailable(SwiftNIO)
endif()

set(BUILD_TESTING ${_NIO_SSL_SAVED_BUILD_TESTING})
set(BUILD_EXAMPLES ${_NIO_SSL_SAVED_BUILD_EXAMPLES})

# Set after vending swift-nio so its targets keep their own language mode.
set(CMAKE_Swift_LANGUAGE_VERSION 6)

add_subdirectory(Sources)
add_subdirectory(cmake/modules)
