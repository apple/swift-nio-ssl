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
import XCTest

@testable import NIOSSL

/// Collects the outputs a `NIOSSLQUICHandshake` hands to its delegate so a test
/// can shuttle handshake bytes to the peer and inspect the negotiated secrets.
private final class CollectingQUICDelegate: NIOSSLQUICDelegate {
    /// Handshake bytes the endpoint wants to send, tagged with their level, in
    /// the order they were produced.
    var outgoing: [(level: NIOTLSEncryptionLevel, bytes: [UInt8])] = []
    var readSecrets: [NIOTLSEncryptionLevel: [UInt8]] = [:]
    var writeSecrets: [NIOTLSEncryptionLevel: [UInt8]] = [:]
    var cipherSuites: [NIOTLSEncryptionLevel: UInt16] = [:]

    func setReadSecret(level: NIOTLSEncryptionLevel, cipherSuite: UInt16, secret: [UInt8]) {
        self.readSecrets[level] = secret
        self.cipherSuites[level] = cipherSuite
    }

    func setWriteSecret(level: NIOTLSEncryptionLevel, cipherSuite: UInt16, secret: [UInt8]) {
        self.writeSecrets[level] = secret
        self.cipherSuites[level] = cipherSuite
    }

    func writeHandshakeData(level: NIOTLSEncryptionLevel, _ data: [UInt8]) {
        self.outgoing.append((level, data))
    }
}

final class NIOSSLQUICHandshakeTests: XCTestCase {
    private static let alpn = "h3"
    private static let clientTransportParameters: [UInt8] = [0x01, 0x02, 0x03, 0x04]
    private static let serverTransportParameters: [UInt8] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e]

    private func makeServerContext(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        let (certificate, privateKey) = generateSelfSignedCert()
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    private func makeClientContext(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        // F1 exercises the handshake mechanism, not certificate verification:
        // the raw QUIC SSL object has no SSLConnection for NIOSSL's verify
        // callback to use, so verification is wired up in a later milestone.
        configuration.certificateVerification = .none
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    /// Hands each buffered flight from `delegate` to `peer` at the level it was
    /// produced, advancing the peer after every flight so its read encryption
    /// level keeps pace (BoringSSL rejects data provided ahead of its current
    /// read level). Returns whether any bytes were transferred and the peer's
    /// resulting state.
    private func feed(
        from delegate: CollectingQUICDelegate,
        into peer: NIOSSLQUICHandshake
    ) throws -> (moved: Bool, state: NIOSSLQUICHandshake.State) {
        var moved = false
        var state = NIOSSLQUICHandshake.State.wantsMoreData
        while !delegate.outgoing.isEmpty {
            let flight = delegate.outgoing.removeFirst()
            var buffer = ByteBuffer()
            buffer.writeBytes(flight.bytes)
            try peer.provideHandshakeData(level: flight.level, buffer)
            state = try peer.advance()
            moved = true
        }
        return (moved, state)
    }

    func testClientServerHandshakeCompletes() throws {
        let clientDelegate = CollectingQUICDelegate()
        let serverDelegate = CollectingQUICDelegate()

        let client = try assertNoThrowWithValue(
            NIOSSLQUICHandshake(
                context: try self.makeClientContext(),
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                delegate: clientDelegate
            )
        )
        let server = try assertNoThrowWithValue(
            NIOSSLQUICHandshake(
                context: try self.makeServerContext(),
                role: .server,
                localTransportParameters: Self.serverTransportParameters,
                delegate: serverDelegate
            )
        )

        // Pump the handshake: the client emits its ClientHello, then each side
        // ferries its output to the peer until both complete. We stop as soon
        // as both are complete, leaving any post-handshake flight (e.g. a
        // NewSessionTicket) unconsumed; that path is covered separately.
        var clientState = try client.advance()
        var serverState = NIOSSLQUICHandshake.State.wantsMoreData
        var rounds = 0
        while rounds < 50 {
            rounds += 1
            let toServer = try self.feed(from: clientDelegate, into: server)
            serverState = toServer.state
            if clientState == .complete, serverState == .complete { break }
            let toClient = try self.feed(from: serverDelegate, into: client)
            clientState = toClient.state
            if clientState == .complete, serverState == .complete { break }
            if !toServer.moved, !toClient.moved { break }
        }

        XCTAssertEqual(clientState, .complete, "client did not complete in \(rounds) rounds")
        XCTAssertEqual(serverState, .complete, "server did not complete in \(rounds) rounds")

        // ALPN was negotiated.
        XCTAssertEqual(client.negotiatedApplicationProtocol, Self.alpn)
        XCTAssertEqual(server.negotiatedApplicationProtocol, Self.alpn)

        // Transport parameters round-tripped through the TLS extension.
        XCTAssertEqual(client.peerTransportParameters, Self.serverTransportParameters)
        XCTAssertEqual(server.peerTransportParameters, Self.clientTransportParameters)

        // The two endpoints derived matching traffic secrets: each side's read
        // secret equals the peer's write secret at the same encryption level.
        for level in [NIOTLSEncryptionLevel.handshake, .application] {
            XCTAssertNotNil(clientDelegate.writeSecrets[level], "no client write secret at \(level)")
            XCTAssertNotNil(serverDelegate.writeSecrets[level], "no server write secret at \(level)")
            XCTAssertEqual(
                clientDelegate.writeSecrets[level],
                serverDelegate.readSecrets[level],
                "client write != server read at \(level)"
            )
            XCTAssertEqual(
                clientDelegate.readSecrets[level],
                serverDelegate.writeSecrets[level],
                "client read != server write at \(level)"
            )
            // A nonzero cipher suite was reported and agreed upon.
            XCTAssertEqual(clientDelegate.cipherSuites[level], serverDelegate.cipherSuites[level])
            XCTAssertNotEqual(clientDelegate.cipherSuites[level], 0)
        }
    }

    func testMalformedPeerDataRaisesFatalAlert() throws {
        // The send_alert trampoline and NIOSSLQUICError.tlsAlert have no other
        // coverage: a complete handshake message of the wrong type in place of
        // the ServerHello makes the client raise a fatal alert, which surfaces
        // as the thrown error (alerts are always fatal in QUIC; the QUIC layer
        // maps them to CONNECTION_CLOSE). The message must be complete — the
        // four-byte header below says type 0x14, one-byte body — because an
        // incomplete one would just buffer awaiting the rest.
        let delegate = CollectingQUICDelegate()
        let client = try assertNoThrowWithValue(
            NIOSSLQUICHandshake(
                context: try self.makeClientContext(),
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                delegate: delegate
            )
        )
        XCTAssertEqual(try client.advance(), .wantsMoreData)

        var garbage = ByteBuffer()
        garbage.writeBytes([0x14, 0x00, 0x00, 0x01, 0x00])
        try client.provideHandshakeData(level: .initial, garbage)
        XCTAssertThrowsError(try client.advance()) { error in
            guard case .tlsAlert(let alert)? = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
            // The exact description depends on how BoringSSL classifies the
            // garbage; what matters is that an alert was raised and surfaced.
            XCTAssertNotEqual(alert, 0)
        }
    }

    func testHandshakeWithoutPeerDataWantsMoreData() throws {
        let serverDelegate = CollectingQUICDelegate()
        let server = try assertNoThrowWithValue(
            NIOSSLQUICHandshake(
                context: try self.makeServerContext(),
                role: .server,
                localTransportParameters: Self.serverTransportParameters,
                delegate: serverDelegate
            )
        )
        // A server with no ClientHello yet cannot make progress.
        XCTAssertEqual(try assertNoThrowWithValue(server.advance()), .wantsMoreData)
        XCTAssertNil(server.peerTransportParameters)
        XCTAssertNil(server.negotiatedApplicationProtocol)
    }
}
