//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// Auto-zeroing storage for data in memory.
///
/// ``NIOSSLSecureBytes`` uses a best-effort strategy to try to remove data from memory when it is no longer in use, by
/// automatically zeroing the heap memory it uses. This is best-effort becuase it's easy for users to accidentally copy
/// data out of this structure. To get its best effect, do not copy this data out into another type, but operate on
/// ``NIOSSLSecureBytes`` generically or specifically.
public struct NIOSSLSecureBytes {
    @usableFromInline
    var backing: Backing

    /// Create an empty ``NIOSSLSecureBytes``.
    @inlinable
    public init() {
        self = .init(count: 0)
    }

    @usableFromInline
    init(count: Int) {
        self.backing = NIOSSLSecureBytes.Backing.create(randomBytes: count)
    }

    init(bytes: [UInt8]) {
        self.backing = Backing.create(bytes: bytes)
    }
    /// Allows initializing a SecureBytes object with a closure that will initialize the memory.
    @usableFromInline
    init(
        unsafeUninitializedCapacity: Int,
        initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void
    ) rethrows {
        self.backing = Backing.create(capacity: unsafeUninitializedCapacity)
        try self.backing._withVeryUnsafeMutableBytes { veryUnsafePointer in
            // As Array does, we want to truncate the initializing pointer to only have the requested size.
            var veryUnsafePointer = UnsafeMutableRawBufferPointer(
                rebasing: veryUnsafePointer.prefix(unsafeUninitializedCapacity)
            )
            var initializedCount = 0
            try callback(&veryUnsafePointer, &initializedCount)

            self.backing.count = initializedCount
        }
    }
}

// NIOSSLSecureBytes is a Copy on Write (CoW) type and therefore Sendable
extension NIOSSLSecureBytes: @unchecked Sendable {}

extension NIOSSLSecureBytes {
    /// Append the contents of a collection of bytes to this ``NIOSSLSecureBytes``.
    ///
    /// - parameter data: The `data` to add to the ``NIOSSLSecureBytes``.
    @inlinable
    mutating public func append<C: Collection>(_ data: C) where C.Element == UInt8 {
        let requiredCapacity = self.count + data.count
        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > self.backing.capacity {
            let newBacking = Backing.create(capacity: requiredCapacity)
            newBacking._appendBytes(self.backing, inRange: 0..<self.count)
            self.backing = newBacking
        }
        self.backing._appendBytes(data)
    }

    mutating public func reserveCapacity(_ n: Int) {
        if self.backing.capacity >= n {
            return
        }

        let newBacking = Backing.create(capacity: n)
        newBacking._appendBytes(self.backing, inRange: 0..<self.count)
        self.backing = newBacking
    }

    @inlinable
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try self.backing.withUnsafeBytes(body)
    }
}

// MARK: - Equatable conformance, constant-time
extension NIOSSLSecureBytes: Equatable {
    static public func == (lhs: NIOSSLSecureBytes, rhs: NIOSSLSecureBytes) -> Bool {
        lhs.backing.withUnsafeBytes { lhsPtr in
            rhs.backing.withUnsafeBytes { rhsPtr in
                constantTimeCompare(lhsPtr, rhsPtr)
            }
        }
    }
}

// MARK: - RandomAccessCollection conformance
extension NIOSSLSecureBytes: RandomAccessCollection {
    @inlinable
    public var startIndex: Int { 0 }

    @inlinable
    public var endIndex: Int { self.count }

    @inlinable
    public var count: Int {
        self.backing.count
    }

    @inlinable
    public subscript(_ index: Int) -> UInt8 {
        get {
            self.backing[offset: index]
        }
        set {
            self.backing[offset: index] = newValue
        }
    }
}

// MARK: - MutableCollection conformance
extension NIOSSLSecureBytes: MutableCollection {}

// MARK: - RangeReplaceableCollection conformance
extension NIOSSLSecureBytes: RangeReplaceableCollection {
    @inlinable
    mutating public func replaceSubrange<C: Collection>(_ subrange: Range<Index>, with newElements: C)
    where C.Element == UInt8 {
        let requiredCapacity = self.backing.count - subrange.count + newElements.count

        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > self.backing.capacity {
            // We have to allocate anyway, so let's use a nice straightforward copy.
            let newBacking = Backing.create(capacity: requiredCapacity)

            let lowerSlice = 0..<subrange.lowerBound
            let upperSlice = subrange.upperBound..<self.count

            newBacking._appendBytes(self.backing, inRange: lowerSlice)
            newBacking._appendBytes(newElements)
            newBacking._appendBytes(self.backing, inRange: upperSlice)

            self.backing = newBacking
            return
        } else {
            // We have room, and a unique pointer. Ask the backing storage to shuffle around.
            let offsetRange = subrange.lowerBound..<subrange.upperBound
            self.backing.replaceSubrangeFittingWithinCapacity(offsetRange, with: newElements)
        }
    }
}

// MARK: - Heap allocated backing storage.
extension NIOSSLSecureBytes {
    @usableFromInline
    internal struct BackingHeader: Sendable {
        @usableFromInline
        internal var count: Int

        @usableFromInline
        internal var capacity: Int
    }

    @usableFromInline
    internal class Backing: ManagedBuffer<BackingHeader, UInt8> {
        @usableFromInline
        class func create(capacity: Int) -> Backing {
            let capacity = Int(UInt32(capacity).nextPowerOf2ClampedToMax())
            return Backing.create(
                minimumCapacity: capacity,
                makingHeaderWith: { _ in BackingHeader(count: 0, capacity: capacity) }
            ) as! Backing
        }

        @usableFromInline
        class func create(copying original: Backing) -> Backing {
            Backing.create(bytes: original.withUnsafeBytes { Array($0) })
        }

        @inlinable
        class func create(bytes: [UInt8]) -> Backing {
            bytes.withUnsafeBytes { bytesPtr in
                let backing = Backing.create(capacity: bytesPtr.count)
                backing._withVeryUnsafeMutableBytes { targetPtr in
                    targetPtr.copyMemory(from: bytesPtr)
                }
                backing.count = bytesPtr.count
                precondition(backing.count <= backing.capacity)
                return backing
            }
        }

        @usableFromInline
        class func create(randomBytes: Int) -> Backing {
            let backing = Backing.create(capacity: randomBytes)
            backing._withVeryUnsafeMutableBytes { targetPtr in
                assert(targetPtr.count >= randomBytes)
                targetPtr.initializeWithRandomBytes(count: randomBytes)
            }
            backing.count = randomBytes
            return backing
        }

        deinit {
            // We always clear the whole capacity, even if we don't think we used it all.
            let bytesToClear = self.header.capacity

            _ = self.withUnsafeMutablePointerToElements { elementsPtr in
                memset_s(elementsPtr, bytesToClear, 0, bytesToClear)
            }
        }

        @usableFromInline
        var count: Int {
            get {
                self.header.count
            }
            set {
                self.header.count = newValue
            }
        }

        @usableFromInline
        subscript(offset offset: Int) -> UInt8 {
            get {
                // precondition(offset >= 0 && offset < self.count)
                self.withUnsafeMutablePointerToElements { ($0 + offset).pointee }
            }
            set {
                // precondition(offset >= 0 && offset < self.count)
                return self.withUnsafeMutablePointerToElements { ($0 + offset).pointee = newValue }
            }
        }
    }
}

// This conformance is technically redundant - Swift 6.2 compiler finally caught this
#if compiler(<6.2)
@available(*, unavailable)
extension NIOSSLSecureBytes.Backing: Sendable {}
#endif

extension NIOSSLSecureBytes.Backing {
    @usableFromInline
    func replaceSubrangeFittingWithinCapacity<C: Collection>(_ subrange: Range<Int>, with newElements: C)
    where C.Element == UInt8 {
        // This function is called when have a unique reference to the backing storage, and we have enough room to store these bytes without
        // any problem. We have one pre-existing buffer made up of 4 regions: a prefix set of bytes that are
        // before the range "subrange", a range of bytes to be replaced (R1), a suffix set of bytes that are after
        // the range "subrange" but within the valid count, and then a region of uninitialized memory. We also have
        // a new set of bytes, R2, that may be larger or smaller than R1, and could indeed be empty!
        //
        // ┌────────────────────────┬──────────────────┬──────────────────┬───────────────┐
        // │         Prefix         │        R1        │      Suffix      │ Uninitialized │
        // └────────────────────────┴──────────────────┴──────────────────┴───────────────┘
        //
        //                ┌─────────────────────────────────────┐
        //                │                  R2                 │
        //                └─────────────────────────────────────┘
        //
        // The minimal number of steps we can take in the general case is two steps. We can't just copy R2 into the space
        // for R1 and then move the suffix, as if R2 is larger than R1 we'll have thrown some suffix bytes away. So we have
        // to move suffix first. What we do is take the bytes in suffix, and move them (via memmove). We can then copy
        // R2 in, and feel confident that the space in memory is right.
        precondition(self.count - subrange.count + newElements.count <= self.capacity, "Insufficient capacity")

        let moveDistance = newElements.count - subrange.count
        let suffixRange = subrange.upperBound..<self.count
        self._moveBytes(range: suffixRange, by: moveDistance)
        self._copyBytes(newElements, at: subrange.lowerBound)
        self.count += newElements.count - subrange.count
    }

    /// Appends the bytes of a collection to this storage, crashing if there is not enough room.
    @inlinable  // private but inlinable
    func _appendBytes<C: Collection>(_ bytes: C) where C.Element == UInt8 {
        let byteCount = bytes.count

        precondition(
            self.capacity - self.count - byteCount >= 0,
            "Insufficient space for byte copying, must have reallocated!"
        )

        let lowerOffset = self.count
        self._withVeryUnsafeMutableBytes { bytesPtr in
            let innerPtrSlice = UnsafeMutableRawBufferPointer(rebasing: bytesPtr[lowerOffset...])
            innerPtrSlice.copyBytes(from: bytes)
        }
        self.count += byteCount
    }

    /// Appends the bytes of a slice of another backing buffer to this storage, crashing if there
    /// is not enough room.
    @inlinable  // private but inlinable
    func _appendBytes(
        _ backing: NIOSSLSecureBytes.Backing,
        inRange range: Range<Int>
    ) {
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= backing.capacity)
        precondition(
            self.capacity - self.count - range.count >= 0,
            "Insufficient space for byte copying, must have reallocated!"
        )

        backing.withUnsafeBytes { backingPtr in
            let ptrSlice = UnsafeRawBufferPointer(rebasing: backingPtr[range])

            let lowerOffset = self.count
            self._withVeryUnsafeMutableBytes { bytesPtr in
                let innerPtrSlice = UnsafeMutableRawBufferPointer(rebasing: bytesPtr[lowerOffset...])
                innerPtrSlice.copyMemory(from: ptrSlice)
            }
            self.count += ptrSlice.count
        }
    }

    /// Moves the range of bytes identified by the slice by the delta, crashing if the move would
    /// place the bytes out of the storage. Note that this does not update the count: external code
    /// must ensure that that happens.
    @usableFromInline  // private but usableFromInline
    func _moveBytes(range: Range<Int>, by delta: Int) {
        // We have to check that the range is within the delta, as is the new location.
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= self.capacity)

        let shiftedRange = (range.lowerBound + delta)..<(range.upperBound + delta)
        precondition(shiftedRange.lowerBound > 0)
        precondition(shiftedRange.upperBound <= self.capacity)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let source = UnsafeRawBufferPointer(rebasing: backingPtr[range])
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[shiftedRange])
            dest.copyMemory(from: source)  // copy memory uses memmove under the hood.
        }
    }

    // Copies some bytes into the buffer at the appropriate place. Does not update count: external code must do so.
    @inlinable  // private but inlinable
    func _copyBytes<C: Collection>(_ bytes: C, at offset: Int) where C.Element == UInt8 {
        precondition(offset >= 0)
        precondition(offset + bytes.count <= self.capacity)

        let byteRange = offset..<(offset + bytes.count)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[byteRange])
            dest.copyBytes(from: bytes)
        }
    }

    @usableFromInline
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            try body(UnsafeRawBufferPointer(start: elementsPtr, count: count))
        }
    }
    @usableFromInline
    func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows -> T {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: count))
        }
    }

    /// Very unsafe in the sense that this points to uninitialized memory. Used only for implementations within this file.
    @inlinable  // private but inlinable
    func _withVeryUnsafeMutableBytes<T>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> T
    ) rethrows -> T {
        let capacity = self.capacity

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: capacity))
        }
    }
}

extension UInt32 {
    /// Returns the next power of two unless that would overflow, in which case UInt32.max (on 64-bit systems) or
    /// Int32.max (on 32-bit systems) is returned. The returned value is always safe to be cast to Int and passed
    /// to malloc on all platforms.
    func nextPowerOf2ClampedToMax() -> UInt32 {
        guard self > 0 else {
            return 1
        }

        var n = self

        #if arch(arm) || arch(i386)
        // on 32-bit platforms we can't make use of a whole UInt32.max (as it doesn't fit in an Int)
        let max = UInt32(Int.max)
        #else
        // on 64-bit platforms we're good
        let max = UInt32.max
        #endif

        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        if n != max {
            n += 1
        }

        return n
    }
}
