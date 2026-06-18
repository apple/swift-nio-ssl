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

/// Drives one `NIOSSLQUICHandshake` and accumulates what it drains after each
/// `advance()`, so a test can shuttle handshake bytes to the peer and inspect
/// the negotiated secrets. The pull-model stand-in for what a collecting
/// delegate used to do.
private final class Endpoint {
    let handshake: NIOSSLQUICHandshake
    /// Handshake bytes the endpoint wants to send, tagged with their level, in
    /// the order they were produced; consumed by `feed(from:into:)`.
    var outgoing: [(level: NIOTLSEncryptionLevel, bytes: [UInt8])] = []
    var readSecrets: [NIOTLSEncryptionLevel: [UInt8]] = [:]
    var writeSecrets: [NIOTLSEncryptionLevel: [UInt8]] = [:]
    var cipherSuites: [NIOTLSEncryptionLevel: UInt16] = [:]

    init(_ handshake: NIOSSLQUICHandshake) {
        self.handshake = handshake
    }

    var negotiatedProtocol: String? { self.handshake.negotiatedProtocol }
    var peerTransportParameters: [UInt8]? { self.handshake.peerTransportParameters }

    func provideHandshakeData(level: NIOTLSEncryptionLevel, _ buffer: ByteBuffer) throws {
        try self.handshake.provideHandshakeData(level: level, buffer)
    }

    /// Advances the handshake, then drains what it produced into the collectors.
    @discardableResult
    func advance() throws -> NIOSSLQUICHandshake.State {
        let state = try self.handshake.advance()
        for secret in self.handshake.drainSecrets() {
            switch secret.direction {
            case .read: self.readSecrets[secret.level] = secret.bytes
            case .write: self.writeSecrets[secret.level] = secret.bytes
            }
            self.cipherSuites[secret.level] = secret.cipherSuite
        }
        for flight in self.handshake.drainHandshakeData() {
            self.outgoing.append((flight.level, flight.data))
        }
        return state
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

    /// Hands each buffered flight from `source` to `peer` at the level it was
    /// produced, advancing the peer after every flight so its read encryption
    /// level keeps pace (BoringSSL rejects data provided ahead of its current
    /// read level). Returns whether any bytes were transferred and the peer's
    /// resulting state.
    private func feed(
        from source: Endpoint,
        into peer: Endpoint
    ) throws -> (moved: Bool, state: NIOSSLQUICHandshake.State) {
        var moved = false
        var state = NIOSSLQUICHandshake.State.wantsMoreData
        while !source.outgoing.isEmpty {
            let flight = source.outgoing.removeFirst()
            var buffer = ByteBuffer()
            buffer.writeBytes(flight.bytes)
            try peer.provideHandshakeData(level: flight.level, buffer)
            state = try peer.advance()
            moved = true
        }
        return (moved, state)
    }

    func testClientServerHandshakeCompletes() throws {
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters
                )
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
            let toServer = try self.feed(from: client, into: server)
            serverState = toServer.state
            if clientState == .complete, serverState == .complete { break }
            let toClient = try self.feed(from: server, into: client)
            clientState = toClient.state
            if clientState == .complete, serverState == .complete { break }
            if !toServer.moved, !toClient.moved { break }
        }

        XCTAssertEqual(clientState, .complete, "client did not complete in \(rounds) rounds")
        XCTAssertEqual(serverState, .complete, "server did not complete in \(rounds) rounds")

        // ALPN was negotiated.
        XCTAssertEqual(client.negotiatedProtocol, Self.alpn)
        XCTAssertEqual(server.negotiatedProtocol, Self.alpn)

        // Transport parameters round-tripped through the TLS extension.
        XCTAssertEqual(client.peerTransportParameters, Self.serverTransportParameters)
        XCTAssertEqual(server.peerTransportParameters, Self.clientTransportParameters)

        // The two endpoints derived matching traffic secrets: each side's read
        // secret equals the peer's write secret at the same encryption level.
        for level in [NIOTLSEncryptionLevel.handshake, .application] {
            XCTAssertNotNil(client.writeSecrets[level], "no client write secret at \(level)")
            XCTAssertNotNil(server.writeSecrets[level], "no server write secret at \(level)")
            XCTAssertEqual(
                client.writeSecrets[level],
                server.readSecrets[level],
                "client write != server read at \(level)"
            )
            XCTAssertEqual(
                client.readSecrets[level],
                server.writeSecrets[level],
                "client read != server write at \(level)"
            )
            // A nonzero cipher suite was reported and agreed upon.
            XCTAssertEqual(client.cipherSuites[level], server.cipherSuites[level])
            XCTAssertNotEqual(client.cipherSuites[level], 0)
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
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters
                )
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

    func testAdvanceProcessesPostHandshakeMessages() throws {
        // A TLS 1.3 server sends NewSessionTickets right after the handshake;
        // in QUIC they arrive as application-level CRYPTO. After completion,
        // advance() must route them through SSL_process_quic_post_handshake
        // (feeding them and calling SSL_do_handshake would silently buffer
        // them forever).
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters
                )
            )
        )
        var clientState = try client.advance()
        var serverState = NIOSSLQUICHandshake.State.wantsMoreData
        var rounds = 0
        while rounds < 50, clientState != .complete || serverState != .complete {
            rounds += 1
            let toServer = try self.feed(from: client, into: server)
            if toServer.moved { serverState = toServer.state }
            let toClient = try self.feed(from: server, into: client)
            if toClient.moved { clientState = toClient.state }
            if !toServer.moved, !toClient.moved { break }
        }
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)

        // The pump above already ferried any post-handshake flight the server
        // produced (its NewSessionTickets) into the client, where the
        // post-completion advance() processed it without error. Prove the
        // post-handshake path also rejects bad input: a complete handshake
        // message of a bogus type must throw from advance(). (An incomplete
        // message would just buffer: the four-byte header below says type 0x20,
        // one-byte body, so the message is whole and gets parsed.)
        var bogus = ByteBuffer()
        bogus.writeBytes([0x20, 0x00, 0x00, 0x01, 0x00])
        try client.provideHandshakeData(level: .application, bogus)
        XCTAssertThrowsError(try client.advance())
    }

    func testHandshakeWithoutPeerDataWantsMoreData() throws {
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters
                )
            )
        )
        // A server with no ClientHello yet cannot make progress.
        XCTAssertEqual(try assertNoThrowWithValue(server.advance()), .wantsMoreData)
        XCTAssertNil(server.peerTransportParameters)
        XCTAssertNil(server.negotiatedProtocol)
    }

    // MARK: Certificate and hostname verification

    /// A server context built from a specific certificate and key, so a client
    /// can be configured to trust that exact certificate.
    private func makeServerContext(
        certificate: NIOSSLCertificate,
        privateKey: NIOSSLPrivateKey,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    /// A client context with the given verification policy, optionally trusting
    /// `certificate` as its sole root.
    private func makeClientContext(
        verification: CertificateVerification,
        trusting certificate: NIOSSLCertificate? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = verification
        if let certificate {
            configuration.trustRoots = .certificates([certificate])
        }
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    /// Pumps a client/server handshake to completion, rethrowing any error a
    /// side raises (e.g. a verification failure surfacing as a fatal alert).
    private func pump(
        client: Endpoint,
        server: Endpoint
    ) throws -> (client: NIOSSLQUICHandshake.State, server: NIOSSLQUICHandshake.State) {
        var clientState = try client.advance()
        var serverState = NIOSSLQUICHandshake.State.wantsMoreData
        var rounds = 0
        while rounds < 50, clientState != .complete || serverState != .complete {
            rounds += 1
            let toServer = try self.feed(from: client, into: server)
            if toServer.moved { serverState = toServer.state }
            let toClient = try self.feed(from: server, into: client)
            if toClient.moved { clientState = toClient.state }
            if !toServer.moved, !toClient.moved { break }
        }
        return (clientState, serverState)
    }

    /// Drives a handshake between a verifying client and a server presenting the
    /// generated self-signed certificate (`CN=localhost`, SAN `DNS:localhost`),
    /// rethrowing whatever the client raises.
    private func runVerifyingHandshake(
        verification: CertificateVerification,
        trustingServerCertificate: Bool,
        serverHostname: String?
    ) throws -> NIOSSLQUICHandshake.State {
        let (certificate, privateKey) = generateSelfSignedCert()
        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeClientContext(
                    verification: verification,
                    trusting: trustingServerCertificate ? certificate : nil
                ),
                role: .client,
                serverHostname: serverHostname,
                localTransportParameters: Self.clientTransportParameters
            )
        )
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeServerContext(certificate: certificate, privateKey: privateKey),
                role: .server,
                localTransportParameters: Self.serverTransportParameters
            )
        )
        return try self.pump(client: client, server: server).client
    }

    func testFullVerificationWithMatchingHostnameCompletes() throws {
        // Trusted certificate, matching name: chain and hostname both pass.
        let state = try assertNoThrowWithValue(
            self.runVerifyingHandshake(
                verification: .fullVerification,
                trustingServerCertificate: true,
                serverHostname: "localhost"
            )
        )
        XCTAssertEqual(state, .complete)
    }

    func testFullVerificationRejectsHostnameMismatch() throws {
        // Trusted certificate, wrong name: SSL_set1_host fails the handshake.
        XCTAssertThrowsError(
            try self.runVerifyingHandshake(
                verification: .fullVerification,
                trustingServerCertificate: true,
                serverHostname: "wrong.example.com"
            )
        ) { error in
            guard case .tlsAlert = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
        }
    }

    func testFullVerificationRejectsUntrustedCertificate() throws {
        // Matching name, but the self-signed certificate is not trusted: chain
        // verification (inherited from the SSL_CTX) fails the handshake.
        XCTAssertThrowsError(
            try self.runVerifyingHandshake(
                verification: .fullVerification,
                trustingServerCertificate: false,
                serverHostname: "localhost"
            )
        ) { error in
            guard case .tlsAlert = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
        }
    }

    func testNoHostnameVerificationAllowsMismatch() throws {
        // Trusted certificate, wrong name: the chain is checked but the name is
        // not, so SNI is set without SSL_set1_host and the handshake completes.
        let state = try assertNoThrowWithValue(
            self.runVerifyingHandshake(
                verification: .noHostnameVerification,
                trustingServerCertificate: true,
                serverHostname: "wrong.example.com"
            )
        )
        XCTAssertEqual(state, .complete)
    }

    func testIPAddressServerHostnameIsRejected() throws {
        // SNI cannot carry an IP address; the handshake init rejects it up front.
        XCTAssertThrowsError(
            try NIOSSLQUICHandshake(
                context: try self.makeClientContext(verification: .fullVerification),
                role: .client,
                serverHostname: "127.0.0.1",
                localTransportParameters: Self.clientTransportParameters
            )
        )
    }
}
