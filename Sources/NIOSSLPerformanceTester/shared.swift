//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import NIOCore
import NIOEmbedded
import NIOSSL

class BackToBackEmbeddedChannel {
    private(set) var client: EmbeddedChannel
    private(set) var server: EmbeddedChannel
    private var loop: EmbeddedEventLoop

    init() {
        self.loop = EmbeddedEventLoop()
        self.client = EmbeddedChannel(loop: self.loop)
        self.server = EmbeddedChannel(loop: self.loop)
    }

    func run() {
        self.loop.run()
    }

    func interactInMemory() throws {
        var workToDo = true

        while workToDo {
            workToDo = false

            self.loop.run()
            let clientDatum = try self.client.readOutbound(as: IOData.self)
            let serverDatum = try self.server.readOutbound(as: IOData.self)

            if let clientMsg = clientDatum {
                try self.server.writeInbound(clientMsg)
                workToDo = true
            }

            if let serverMsg = serverDatum {
                try self.client.writeInbound(serverMsg)
                workToDo = true
            }
        }
    }
}

extension NIOSSLCertificate {
    static func forTesting() throws -> NIOSSLCertificate {
        try .init(bytes: certificatePemBytes, format: .pem)
    }
}

extension NIOSSLPrivateKey {
    static func forTesting() throws -> NIOSSLPrivateKey {
        try .init(bytes: keyPemBytes, format: .pem)
    }
}

private let certificatePemBytes = Array(
    """
    -----BEGIN CERTIFICATE-----
    MIIBTzCB9qADAgECAhQkvv72Je/v+B/cgJ53f84O82z6WTAKBggqhkjOPQQDAjAU
    MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTkxMTI3MTAxMjMwWhcNMjkxMTI0MTAx
    MjMwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
    BwNCAAShtZ9TRt7I+7Y0o99XUkrgSYmUmpr4K8CB0IkTCX6b1tXp3Xqs1V5BckTd
    qrls+zsm3AfeiNBb9EDdxiX9DdzuoyYwJDAUBgNVHREEDTALgglsb2NhbGhvc3Qw
    DAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiAKxYON+YTnIHNR0R6SLP8R
    R7hjsjV5NDs18XLoeRnA1gIhANwyggmE6NQW/r9l59fexj/ZrjaS3jYOTNCfC1Lo
    5NgJ
    -----END CERTIFICATE-----
    """.utf8
)

private let keyPemBytes = Array(
    """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCn182hBmYVMAiNPO
    +7w05F40SlAqqxgBEYJZOeK47aihRANCAAShtZ9TRt7I+7Y0o99XUkrgSYmUmpr4
    K8CB0IkTCX6b1tXp3Xqs1V5BckTdqrls+zsm3AfeiNBb9EDdxiX9Ddzu
    -----END PRIVATE KEY-----
    """.utf8
)
