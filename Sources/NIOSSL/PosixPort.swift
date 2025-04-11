//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

// This file contains a version of the SwiftNIO Posix enum. This is necessary
// because SwiftNIO's version is internal. Our version exists for the same reason:
// to ensure errno is captured correctly when doing syscalls, and that no ARC traffic
// can happen inbetween that *could* change the errno value before we were able to
// read it.
//
// The code is an exact port from SwiftNIO, so if that version ever becomes public we
// can lift anything missing from there and move it over without change.
#if canImport(Darwin)
import Darwin.C
#elseif canImport(Musl)
import Musl
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#else
#error("unsupported os")
#endif

#if os(Android)
internal typealias FILEPointer = OpaquePointer
#else
internal typealias FILEPointer = UnsafeMutablePointer<FILE>
#endif

private let sysFopen = fopen
private let sysMlock = mlock
private let sysMunlock = munlock
private let sysFclose = fclose
private let sysStat = { @Sendable in stat($0, $1) }
private let sysLstat = lstat
private let sysReadlink = readlink

// MARK:- Copied code from SwiftNIO
private func isUnacceptableErrno(_ code: CInt) -> Bool {
    switch code {
    case EFAULT, EBADF:
        return true
    default:
        return false
    }
}

// Sorry, we really try hard to not use underscored attributes. In this case however we seem to break the inlining threshold which makes a system call take twice the time, ie. we need this exception.
@inline(__always)
internal func wrapSyscall<T: FixedWidthInteger>(where function: String = #function, _ body: () throws -> T) throws -> T
{
    while true {
        let res = try body()
        if res == -1 {
            let err = errno
            if err == EINTR {
                continue
            }
            assert(!isUnacceptableErrno(err), "unacceptable errno \(err) \(strerror(err)!)")
            throw IOError(errnoCode: err, reason: function)
        }
        return res
    }
}

// Sorry, we really try hard to not use underscored attributes. In this case however we seem to break the inlining threshold which makes a system call take twice the time, ie. we need this exception.
@inline(__always)
internal func wrapErrorIsNullReturnCall<T>(
    errorReason: @autoclosure () -> String = #function,
    _ body: () throws -> T?
) throws -> T {
    while true {
        guard let res = try body() else {
            let err = errno
            if err == EINTR {
                continue
            }
            assert(!isUnacceptableErrno(err), "unacceptable errno \(err) \(strerror(err)!)")
            throw IOError(errnoCode: err, reason: errorReason())
        }
        return res
    }
}

// MARK:- Our functions
internal enum Posix {
    @inline(never)
    internal static func fopen(file: String, mode: String) throws -> FILEPointer {
        try file.withCString { fileCString in
            try wrapErrorIsNullReturnCall(errorReason: "fopen(file: \"\(file)\", mode: \"\(mode)\")") {
                sysFopen(fileCString, mode)
            }
        }
    }

    @inline(never)
    internal static func fclose(file: FILEPointer) throws -> CInt {
        try wrapSyscall {
            sysFclose(file)
        }
    }

    @inline(never)
    internal static func readlink(
        path: UnsafePointer<Int8>,
        buf: UnsafeMutablePointer<Int8>,
        bufSize: Int
    ) throws -> Int {
        try wrapSyscall {
            sysReadlink(path, buf, bufSize)
        }
    }

    @inline(never)
    @discardableResult
    internal static func stat(path: UnsafePointer<CChar>, buf: UnsafeMutablePointer<stat>) throws -> CInt {
        try wrapSyscall {
            sysStat(path, buf)
        }
    }

    @inline(never)
    @discardableResult
    internal static func lstat(path: UnsafePointer<Int8>, buf: UnsafeMutablePointer<stat>) throws -> Int32 {
        try wrapSyscall {
            sysLstat(path, buf)
        }
    }

    @inline(never)
    @discardableResult
    internal static func mlock(addr: UnsafeRawPointer, len: size_t) throws -> CInt {
        try wrapSyscall {
            sysMlock(addr, len)
        }
    }

    @inline(never)
    @discardableResult
    internal static func munlock(addr: UnsafeRawPointer, len: size_t) throws -> CInt {
        try wrapSyscall {
            sysMunlock(addr, len)
        }
    }
}
