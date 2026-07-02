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
    /// A custom certificate verifier. When set, `advance()` resolves a
    /// `wantsCertificateVerify` park inline by calling this with the peer chain
    /// and feeding its verdict back through `resumeVerification(_:)`. `nil`
    /// leaves the park surfaced for the caller to inspect.
    var verify: (([NIOSSLCertificate]) -> NIOSSLVerificationResult)?
    /// The peer chain last handed to `verify`, recorded so a test can assert
    /// what the application saw.
    var verifiedChain: [NIOSSLCertificate]?
    /// A transport-parameter selector. When set, `advance()` resolves a
    /// `wantsTransportParameters` park inline by calling this with the peer's
    /// encoded parameters and feeding its decision back through
    /// `resumeTransportParameters(_:)`. `nil` leaves the park surfaced.
    var selectTransportParameters: (([UInt8]) -> NIOSSLQUICHandshake.TransportParametersDecision)?
    /// The peer parameters last handed to `selectTransportParameters`, recorded
    /// so a test can assert what the application saw.
    var selectedFromPeer: [UInt8]?

    init(_ handshake: NIOSSLQUICHandshake) {
        self.handshake = handshake
    }

    var negotiatedProtocol: String? { self.handshake.negotiatedProtocol }
    var peerTransportParameters: [UInt8]? { self.handshake.peerTransportParameters }

    func provideHandshakeData(level: NIOTLSEncryptionLevel, _ buffer: ByteBuffer) throws {
        try self.handshake.provideHandshakeData(level: level, buffer)
    }

    /// Advances the handshake, draining what each step produces into the
    /// collectors. A `wantsCertificateVerify` or `wantsTransportParameters` park
    /// is resolved inline when its provider is set—record the input, supply the
    /// verdict or decision, advance again—so the pump treats each as a single
    /// step. A park with no provider is surfaced for the caller to inspect.
    @discardableResult
    func advance() throws -> NIOSSLQUICHandshake.State {
        var state = try self.handshake.advance()
        self.drain()
        loop: while true {
            switch state {
            case .wantsCertificateVerify(let chain):
                guard let verify = self.verify else { break loop }
                self.verifiedChain = chain
                self.handshake.resumeVerification(verify(chain))
            case .wantsTransportParameters(let peer):
                guard let select = self.selectTransportParameters else { break loop }
                self.selectedFromPeer = peer
                self.handshake.resumeTransportParameters(select(peer))
            default:
                break loop
            }
            state = try self.handshake.advance()
            self.drain()
        }
        return state
    }

    /// Moves the secrets and handshake bytes the last `advance()` produced out
    /// of the handshake and into the collectors.
    private func drain() {
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
    }
}

final class NIOSSLQUICHandshakeTests: XCTestCase {
    private static let alpn = "h3"
    private static let clientTransportParameters: [UInt8] = [0x01, 0x02, 0x03, 0x04]
    private static let serverTransportParameters: [UInt8] = [0x0a, 0x0b, 0x0c, 0x0d, 0x0e]
    /// A distinct set a selection hook returns, to tell it apart from the default
    /// `serverTransportParameters` on the wire.
    private static let chosenTransportParameters: [UInt8] = [0xf0, 0xf1, 0xf2]

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
        // maps them to CONNECTION_CLOSE). The message must be complete—the
        // four-byte header below says type 0x14, one-byte body—because an
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
                localTransportParameters: Self.clientTransportParameters,
                serverHostname: serverHostname
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
                localTransportParameters: Self.clientTransportParameters,
                serverHostname: "127.0.0.1"
            )
        )
    }

    // MARK: Custom certificate verification

    /// A client that hands the peer chain to `verify` instead of verifying it
    /// built-in, paired with a server presenting the generated self-signed
    /// certificate. The client context trusts nothing and the server hostname,
    /// when given, need not match the certificate—under custom verification
    /// the verifier owns both trust and the name check.
    private func makeCustomVerifyingPair(
        serverHostname: String?,
        verify: @escaping ([NIOSSLCertificate]) -> NIOSSLVerificationResult
    ) throws -> (client: Endpoint, server: Endpoint, certificate: NIOSSLCertificate) {
        let (certificate, privateKey) = generateSelfSignedCert()
        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeClientContext(verification: .none),
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                serverHostname: serverHostname,
                customCertificateVerification: true
            )
        )
        client.verify = verify
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeServerContext(certificate: certificate, privateKey: privateKey),
                role: .server,
                localTransportParameters: Self.serverTransportParameters
            )
        )
        return (client, server, certificate)
    }

    func testCustomVerificationOwnsTrustAndCompletes() throws {
        // The application's verdict replaces both the SSL_CTX trust check and the
        // built-in name check: a client trusting nothing, sending a hostname that
        // does not match the certificate, still completes when the verifier
        // approves the chain. The chain it saw is the server's leaf certificate.
        let (client, server, certificate) = try self.makeCustomVerifyingPair(
            serverHostname: "wrong.example.com",
            verify: { _ in .certificateVerified }
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(client.verifiedChain?.first, certificate)
    }

    func testCustomVerificationRejectionFailsHandshake() throws {
        // A `.failed` verdict becomes ssl_verify_invalid, which fails the
        // handshake with a fatal certificate alert—surfaced, like any QUIC
        // alert, as a thrown NIOSSLQUICError.tlsAlert.
        let (client, server, _) = try self.makeCustomVerifyingPair(
            serverHostname: "localhost",
            verify: { _ in .failed }
        )
        XCTAssertThrowsError(try self.pump(client: client, server: server)) { error in
            guard case .tlsAlert = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
        }
        // The chain reached the verifier before the verdict was rendered.
        XCTAssertNotNil(client.verifiedChain)
        XCTAssertFalse(client.verifiedChain?.isEmpty ?? true)
    }

    func testDefaultLeavesVerificationToTheContext() throws {
        // Without customCertificateVerification the handshake never parks for the
        // application: the verifier is left untouched and the context's policy
        // (.none here) decides. A verify closure wired up anyway must never run.
        let (certificate, privateKey) = generateSelfSignedCert()
        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeClientContext(verification: .none),
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                serverHostname: "localhost"
            )
        )
        client.verify = { _ in
            XCTFail("custom verifier ran without customCertificateVerification")
            return .certificateVerified
        }
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: try self.makeServerContext(certificate: certificate, privateKey: privateKey),
                role: .server,
                localTransportParameters: Self.serverTransportParameters
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertNil(client.verifiedChain)
    }

    // MARK: Mutual TLS (a server verifying the client)

    /// A client context that presents `certificate` as its own certificate for
    /// mutual TLS (RFC 9001 § 4), verifying the server with `.none`.
    private func makeClientContext(
        presenting certificate: NIOSSLCertificate,
        privateKey: NIOSSLPrivateKey,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.certificateVerification = .none
        configuration.certificateChain = [.certificate(certificate)]
        configuration.privateKey = .privateKey(privateKey)
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    func testMutualTLSServerVerifiesClientCertificate() throws {
        // customCertificateVerification on a server makes it request the client's
        // certificate (RFC 9001 § 4); the client presents one, and the server's
        // verifier approves it and is handed the client's chain.
        let (clientCertificate, clientKey) = generateSelfSignedCert()
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(presenting: clientCertificate, privateKey: clientKey),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    serverHostname: "localhost"
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters,
                    customCertificateVerification: true
                )
            )
        )
        server.verify = { _ in .certificateVerified }
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(server.verifiedChain?.first, clientCertificate)
    }

    func testMutualTLSServerRejectsClientCertificate() throws {
        // A `.failed` verdict on the client's chain fails the handshake with the
        // certificate alert, the mirror of the client-side rejection.
        let (clientCertificate, clientKey) = generateSelfSignedCert()
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(presenting: clientCertificate, privateKey: clientKey),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    serverHostname: "localhost"
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters,
                    customCertificateVerification: true
                )
            )
        )
        server.verify = { _ in .failed }
        XCTAssertThrowsError(try self.pump(client: client, server: server)) { error in
            guard case .tlsAlert = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
        }
        // The client's chain reached the server's verifier before the verdict.
        XCTAssertNotNil(server.verifiedChain)
        XCTAssertFalse(server.verifiedChain?.isEmpty ?? true)
    }

    func testMutualTLSOptionalClientSendsNoCertificate() throws {
        // Client authentication is optional (no SSL_VERIFY_FAIL_IF_NO_PEER_CERT):
        // a client that presents no certificate still completes the handshake.
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    serverHostname: "localhost"
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters,
                    customCertificateVerification: true
                )
            )
        )
        // With optional client auth, BoringSSL does not consult the verifier when
        // the client presents no certificate, so a server cannot reject an
        // anonymous client through `verify`—the handshake simply completes.
        var verifierRan = false
        server.verify = { _ in
            verifierRan = true
            return .certificateVerified
        }
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertFalse(verifierRan, "optional client auth: no certificate means the verifier is not consulted")
        XCTAssertNil(server.verifiedChain)
    }

    /// A server context that requires the client to present a certificate
    /// (`certificateVerification` mapping to `SSL_VERIFY_FAIL_IF_NO_PEER_CERT`).
    /// A trust root is set so the context builds; the custom verifier overrides
    /// the built-in chain check regardless.
    private func makeRequiringServerContext(
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> NIOSSLContext {
        let (certificate, privateKey) = generateSelfSignedCert()
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(certificate)],
            privateKey: .privateKey(privateKey)
        )
        configuration.certificateVerification = .fullVerification
        configuration.trustRoots = .certificates([certificate])
        configuration.applicationProtocols = [Self.alpn]
        return try assertNoThrowWithValue(NIOSSLContext(configuration: configuration), file: file, line: line)
    }

    func testMutualTLSRequiredRejectsClientWithoutCertificate() throws {
        // certificateVerification .fullVerification requires the client to present
        // a certificate: a client that sends none fails the handshake before the
        // verifier runs (SSL_VERIFY_FAIL_IF_NO_PEER_CERT).
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    serverHostname: "localhost"
                )
            )
        )
        var verifierRan = false
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeRequiringServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters,
                    customCertificateVerification: true
                )
            )
        )
        server.verify = { _ in
            verifierRan = true
            return .certificateVerified
        }
        XCTAssertThrowsError(try self.pump(client: client, server: server)) { error in
            guard case .tlsAlert = error as? NIOSSLQUICError else {
                XCTFail("expected NIOSSLQUICError.tlsAlert, got \(error)")
                return
            }
        }
        XCTAssertFalse(verifierRan, "a missing required client certificate fails before the verifier")
    }

    func testMutualTLSRequiredCompletesWithClientCertificate() throws {
        // With the client presenting a certificate, a requiring server verifies it
        // through the same park/resume and completes.
        let (clientCertificate, clientKey) = generateSelfSignedCert()
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(presenting: clientCertificate, privateKey: clientKey),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    serverHostname: "localhost"
                )
            )
        )
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeRequiringServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters,
                    customCertificateVerification: true
                )
            )
        )
        server.verify = { _ in .certificateVerified }
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(server.verifiedChain?.first, clientCertificate)
    }

    // MARK: Transport parameter selection (a server choosing after the ClientHello)

    /// A client paired with a server that selects its transport parameters with
    /// `select` after seeing the client's (RFC 9000 § 7.4). The client trusts
    /// nothing and verification is off—this exercises the selection seam, not
    /// certificate handling.
    private func makeSelectingPair(
        select: @escaping ([UInt8]) -> NIOSSLQUICHandshake.TransportParametersDecision
    ) throws -> (client: Endpoint, server: Endpoint) {
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
                    localTransportParameters: Self.serverTransportParameters,
                    selectsTransportParameters: true
                )
            )
        )
        server.selectTransportParameters = select
        return (client, server)
    }

    func testTransportParameterSelectionChoosesAfterSeeingPeer() throws {
        // The hook is handed the client's offer and returns a different set; the
        // chosen value, not the configured default, reaches the wire—the client
        // reads back exactly what the hook returned.
        let (client, server) = try self.makeSelectingPair(
            select: { _ in .parameters(Self.chosenTransportParameters) }
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        // The hook saw the client's parameters as its input (§ 7.4).
        XCTAssertEqual(server.selectedFromPeer, Self.clientTransportParameters)
        // The client received the chosen set, not the server's configured default.
        XCTAssertEqual(client.peerTransportParameters, Self.chosenTransportParameters)
        XCTAssertNotEqual(client.peerTransportParameters, Self.serverTransportParameters)
    }

    func testTransportParameterSelectionEchoingDefaultCompletes() throws {
        // Returning the default unchanged is a valid choice: the resume path sets
        // it and the handshake completes, the client reading back the default.
        let (client, server) = try self.makeSelectingPair(
            select: { _ in .parameters(Self.serverTransportParameters) }
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(client.peerTransportParameters, Self.serverTransportParameters)
    }

    func testTransportParameterSelectionAbortFailsHandshake() throws {
        // A `.abort` decision makes the cert_cb return zero, which fails the
        // server's handshake—surfaced as a thrown error from its advance().
        let (client, server) = try self.makeSelectingPair(select: { _ in .abort })
        XCTAssertThrowsError(try self.pump(client: client, server: server))
        // The hook still saw the client's offer before deciding to abort.
        XCTAssertEqual(server.selectedFromPeer, Self.clientTransportParameters)
    }

    func testTransportParameterSelectionOffAdvertisesConfiguredParameters() throws {
        // Without selectsTransportParameters the server never parks: the
        // configured parameters reach the wire and a selector wired up anyway
        // must never run (the park is the only thing that would call it).
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
        server.selectTransportParameters = { _ in
            XCTFail("selector ran without selectsTransportParameters")
            return .parameters(Self.chosenTransportParameters)
        }
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(client.peerTransportParameters, Self.serverTransportParameters)
        XCTAssertNil(server.selectedFromPeer)
    }

    func testTransportParameterSelectionIgnoredForClient() throws {
        // Selection is server-only: a client built with selectsTransportParameters
        // never parks (its parameters ship in the first flight, before any peer),
        // so its configured parameters reach the wire unchanged.
        let client = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeClientContext(),
                    role: .client,
                    localTransportParameters: Self.clientTransportParameters,
                    selectsTransportParameters: true
                )
            )
        )
        client.selectTransportParameters = { _ in
            XCTFail("a client must not park for transport-parameter selection")
            return .parameters(Self.chosenTransportParameters)
        }
        let server = Endpoint(
            try assertNoThrowWithValue(
                NIOSSLQUICHandshake(
                    context: try self.makeServerContext(),
                    role: .server,
                    localTransportParameters: Self.serverTransportParameters
                )
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertEqual(server.peerTransportParameters, Self.clientTransportParameters)
        XCTAssertNil(client.selectedFromPeer)
    }

    // MARK: Session resumption

    /// Runs a full handshake and returns a session ticket the server issued,
    /// captured on the client via ``drainNewSessions()``—the input to a later
    /// resuming handshake.
    private func resumableSession(
        clientContext: NIOSSLContext,
        serverContext: NIOSSLContext
    ) throws -> [UInt8] {
        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: clientContext,
                role: .client,
                localTransportParameters: Self.clientTransportParameters
            )
        )
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: serverContext,
                role: .server,
                localTransportParameters: Self.serverTransportParameters
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertFalse(client.handshake.sessionReused, "the first handshake should be full, not resumed")
        // The server's NewSessionTicket flight follows the handshake; the pump
        // ferries it, but flush any straggler to the client to be safe.
        var sessions = client.handshake.drainNewSessions()
        var rounds = 0
        while sessions.isEmpty, rounds < 5, !server.outgoing.isEmpty {
            rounds += 1
            _ = try self.feed(from: server, into: client)
            sessions.append(contentsOf: client.handshake.drainNewSessions())
        }
        return try XCTUnwrap(sessions.first, "server issued no resumable session")
    }

    func testSessionResumptionReusesTheSession() throws {
        // A ticket from a first handshake, offered on a second, yields an
        // abbreviated (resumed) handshake (RFC 8446 § 2.2). The contexts are
        // reused so the client's session cache and the server's ticket key persist.
        let clientContext = try self.makeClientContext()
        let serverContext = try self.makeServerContext()
        let session = try self.resumableSession(clientContext: clientContext, serverContext: serverContext)

        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: clientContext,
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                resumption: .resume(session: session)
            )
        )
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: serverContext,
                role: .server,
                localTransportParameters: Self.serverTransportParameters
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertTrue(client.handshake.sessionReused, "the second handshake did not resume the session")
    }

    func testResumingWithCorruptSessionThrows() throws {
        // Unparseable session bytes are storage corruption, not something to
        // resume past: the initializer throws rather than silently continue.
        XCTAssertThrowsError(
            try NIOSSLQUICHandshake(
                context: try self.makeClientContext(),
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                resumption: .resume(session: [0x00, 0x01, 0x02, 0x03])
            )
        )
    }

    /// A ticket the issuing server minted with early data enabled, captured on the
    /// client—the input to a 0-RTT resuming handshake.
    private func earlyDataSession(
        clientContext: NIOSSLContext,
        serverContext: NIOSSLContext,
        earlyDataContext: [UInt8]
    ) throws -> [UInt8] {
        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: clientContext,
                role: .client,
                localTransportParameters: Self.clientTransportParameters
            )
        )
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: serverContext,
                role: .server,
                localTransportParameters: Self.serverTransportParameters,
                resumption: .acceptEarlyData(context: earlyDataContext)
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        var sessions = client.handshake.drainNewSessions()
        var rounds = 0
        while sessions.isEmpty, rounds < 5, !server.outgoing.isEmpty {
            rounds += 1
            _ = try self.feed(from: server, into: client)
            sessions.append(contentsOf: client.handshake.drainNewSessions())
        }
        return try XCTUnwrap(sessions.first, "server issued no resumable session")
    }

    func testOfferedEarlyDataIsAccepted() throws {
        // A ticket minted with early data enabled, offered with 0-RTT on a second
        // handshake whose server accepts the same context, is accepted end to end:
        // both sides report `earlyDataAccepted` (RFC 9001 § 4.6). The contexts are
        // reused so the client's session cache and the server's ticket key persist.
        let clientContext = try self.makeClientContext()
        let serverContext = try self.makeServerContext()
        let earlyDataContext = Array("nioquic".utf8)
        let session = try self.earlyDataSession(
            clientContext: clientContext,
            serverContext: serverContext,
            earlyDataContext: earlyDataContext
        )

        let client = Endpoint(
            try NIOSSLQUICHandshake(
                context: clientContext,
                role: .client,
                localTransportParameters: Self.clientTransportParameters,
                resumption: .offerEarlyData(session: session)
            )
        )
        let server = Endpoint(
            try NIOSSLQUICHandshake(
                context: serverContext,
                role: .server,
                localTransportParameters: Self.serverTransportParameters,
                resumption: .acceptEarlyData(context: earlyDataContext)
            )
        )
        let (clientState, serverState) = try self.pump(client: client, server: server)
        XCTAssertEqual(clientState, .complete)
        XCTAssertEqual(serverState, .complete)
        XCTAssertTrue(client.handshake.sessionReused, "the second handshake did not resume the session")
        XCTAssertTrue(client.handshake.earlyDataAccepted, "the client did not see its 0-RTT accepted")
        XCTAssertTrue(server.handshake.earlyDataAccepted, "the server did not accept the offered 0-RTT")
    }
}
