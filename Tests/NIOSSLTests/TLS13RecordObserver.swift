//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import NIOCore

final class TLS13RecordObserver: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    var writtenRecords: [Record] = []

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var payload = self.unwrapOutboundIn(data)

        while let record = payload.readTLS13Record() {
            writtenRecords.append(record)
        }

        // We should have consumed everything as NIO only writes full records.
        precondition(payload.readableBytes == 0)

        // Forward the original payload on.
        context.write(data, promise: promise)
    }
}

extension TLS13RecordObserver {
    struct Record: Hashable {
        var contentType: ContentType
        var legacyRecordVersion: UInt16
        var encryptedRecord: ByteBuffer
    }
}

extension TLS13RecordObserver.Record {
    struct ContentType: RawRepresentable, Hashable {
        var rawValue: UInt8

        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        static let invalid = Self(rawValue: 0)
        static let changeCipherSpec = Self(rawValue: 20)
        static let alert = Self(rawValue: 21)
        static let handshake = Self(rawValue: 22)
        static let applicationData = Self(rawValue: 23)
    }
}

extension ByteBuffer {
    fileprivate mutating func readTLS13Record() -> TLS13RecordObserver.Record? {
        guard
            let (contentType, legacyRecordVersion, length) = self.readMultipleIntegers(as: (UInt8, UInt16, UInt16).self)
        else {
            return nil
        }

        guard let encryptedRecord = self.readSlice(length: Int(length)) else {
            return nil
        }

        return .init(
            contentType: .init(rawValue: contentType),
            legacyRecordVersion: legacyRecordVersion,
            encryptedRecord: encryptedRecord
        )
    }
}
