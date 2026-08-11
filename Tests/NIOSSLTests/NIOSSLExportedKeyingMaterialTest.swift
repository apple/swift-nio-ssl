//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import NIOTLS
import XCTest

@testable import NIOSSL

final class NIOSSLExportedKeyingMaterialTest: XCTestCase {
    private static let (cert, key) = generateSelfSignedCert()

    private func connectedChannels(
        minimumTLSVersion: TLSVersion,
        maximumTLSVersion: TLSVersion
    ) throws -> BackToBackEmbeddedChannel {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([Self.cert])
        clientConfig.minimumTLSVersion = minimumTLSVersion
        clientConfig.maximumTLSVersion = maximumTLSVersion
        var serverConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(Self.cert)],
            privateKey: .privateKey(Self.key)
        )
        serverConfig.minimumTLSVersion = minimumTLSVersion
        serverConfig.maximumTLSVersion = maximumTLSVersion

        let clientContext = try NIOSSLContext(configuration: clientConfig)
        let serverContext = try NIOSSLContext(configuration: serverConfig)
        let b2b = BackToBackEmbeddedChannel()
        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"),
            HandshakeCompletedHandler(),
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([
            NIOSSLServerHandler(context: serverContext),
            HandshakeCompletedHandler(),
        ])
        try b2b.connectInMemory()
        return b2b
    }

    func testClientAndServerAgreeOnExportedMaterial_TLS12() throws {
        let b2b = try connectedChannels(minimumTLSVersion: .tlsv12, maximumTLSVersion: .tlsv12)

        let client = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: nil,
            outputByteCount: 32
        )
        let server = try b2b.server.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: nil,
            outputByteCount: 32
        )
        XCTAssertEqual(client, server)
        XCTAssertEqual(client.count, 32)
    }

    func testClientAndServerAgreeOnExportedMaterial_TLS13() throws {
        let b2b = try connectedChannels(minimumTLSVersion: .tlsv13, maximumTLSVersion: .tlsv13)

        let client = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: [1, 2, 3],
            outputByteCount: 32
        )
        let server = try b2b.server.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: [1, 2, 3],
            outputByteCount: 32
        )
        XCTAssertEqual(client, server)
    }

    func testDifferentLabels() throws {
        let b2b = try connectedChannels(minimumTLSVersion: .tlsv12, maximumTLSVersion: .tlsv12)

        let a = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label-a",
            context: nil,
            outputByteCount: 32
        )
        let b = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label-b",
            context: nil,
            outputByteCount: 32
        )
        XCTAssertNotEqual(a, b)
    }

    func testNilAndEmptyContextDifferBelowTLS13() throws {
        let b2b = try connectedChannels(minimumTLSVersion: .tlsv12, maximumTLSVersion: .tlsv12)

        let withNil = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: nil,
            outputByteCount: 32
        )
        let withEmptyContext = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: [],
            outputByteCount: 32
        )
        XCTAssertNotEqual(withNil, withEmptyContext)
    }

    func testNilAndEmptyContextMatchOnTLS13() throws {
        let b2b = try connectedChannels(minimumTLSVersion: .tlsv13, maximumTLSVersion: .tlsv13)

        let withNil = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: nil,
            outputByteCount: 32
        )
        let withEmptyContext = try b2b.client.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
            label: "test label",
            context: [],
            outputByteCount: 32
        )
        XCTAssertEqual(withNil, withEmptyContext)
    }

    func testExportingBeforeHandshakeCompletionThrows() throws {
        var clientConfig = TLSConfiguration.makeClientConfiguration()
        clientConfig.certificateVerification = .noHostnameVerification
        clientConfig.trustRoots = .certificates([Self.cert])
        let clientContext = try NIOSSLContext(configuration: clientConfig)

        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
        )

        XCTAssertThrowsError(
            try channel.pipeline.syncOperations.nioSSL_exportKeyingMaterial(
                label: "label",
                context: nil,
                outputByteCount: 32
            )
        ) { error in
            guard let boringSSLError = error as? BoringSSLError, case .unableToExportKeyingMaterial = boringSSLError
            else {
                XCTFail("Expected BoringSSLError.unableToExportKeyingMaterial, got \(error)")
                return
            }
        }
    }

}
