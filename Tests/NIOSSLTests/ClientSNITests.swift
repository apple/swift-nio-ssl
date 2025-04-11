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
import NIOPosix
import NIOSSL
import NIOTLS
import XCTest

class ClientSNITests: XCTestCase {
    private func configuredSSLContext() throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        config.trustRoots = .certificates([NIOSSLIntegrationTest.cert])
        let context = try NIOSSLContext(configuration: config)
        return context
    }

    private func assertSniResult(sniField: String?, expectedResult: SNIResult) throws {
        let context = try configuredSSLContext()

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }

        let sniPromise: EventLoopPromise<SNIResult> = group.next().makePromise()
        let serverChannel = try serverTLSChannel(
            context: context,
            preHandlers: [
                ByteToMessageHandler(
                    SNIHandler {
                        sniPromise.succeed($0)
                        return group.next().makeSucceededFuture(())
                    }
                )
            ],
            postHandlers: [],
            group: group
        )
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(
            context: context,
            preHandlers: [],
            postHandlers: [],
            group: group,
            connectingTo: serverChannel.localAddress!,
            serverHostname: sniField
        )
        defer {
            _ = try? clientChannel.close().wait()
        }

        let sniResult = try sniPromise.futureResult.wait()
        XCTAssertEqual(sniResult, expectedResult)
    }

    func testSNIIsTransmitted() throws {
        try assertSniResult(sniField: "httpbin.org", expectedResult: .hostname("httpbin.org"))
    }

    func testNoSNILeadsToNoExtension() throws {
        try assertSniResult(sniField: nil, expectedResult: .fallback)
    }

    func testSNIIsRejectedForIPv4Addresses() throws {
        let context = try configuredSSLContext()

        let testString = "192.168.0.1"
        XCTAssertThrowsError(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        { error in
            XCTAssertEqual(.cannotUseIPAddressInSNI, error as? NIOSSLExtraError)
        }
        XCTAssertThrowsError(try NIOSSLClientHandler(context: context, serverHostname: testString)) { error in
            XCTAssertEqual(.cannotUseIPAddressInSNI, error as? NIOSSLExtraError)
        }
    }

    func testSNIIsRejectedForIPv6Addresses() throws {
        let context = try configuredSSLContext()

        let testString = "fe80::200:f8ff:fe21:67cf"
        XCTAssertThrowsError(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        { error in
            XCTAssertEqual(.cannotUseIPAddressInSNI, error as? NIOSSLExtraError)
        }
        XCTAssertThrowsError(try NIOSSLClientHandler(context: context, serverHostname: testString)) { error in
            XCTAssertEqual(.cannotUseIPAddressInSNI, error as? NIOSSLExtraError)
        }

    }

    func testSNIIsRejectedForEmptyHostname() throws {
        let context = try configuredSSLContext()

        let testString = ""
        XCTAssertThrowsError(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
        XCTAssertThrowsError(try NIOSSLClientHandler(context: context, serverHostname: testString)) { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
    }

    func testSNIIsRejectedForTooLongHostname() throws {
        let context = try configuredSSLContext()

        let testString = String(repeating: "x", count: 256)
        XCTAssertThrowsError(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
        XCTAssertThrowsError(try NIOSSLClientHandler(context: context, serverHostname: testString)) { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
    }

    func testSNIIsRejectedFor0Byte() throws {
        let context = try configuredSSLContext()

        let testString = String(UnicodeScalar(0)!)
        XCTAssertThrowsError(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
        XCTAssertThrowsError(try NIOSSLClientHandler(context: context, serverHostname: testString)) { error in
            XCTAssertEqual(.invalidSNIHostname, error as? NIOSSLExtraError)
        }
    }

    func testSNIIsNotRejectedForAnyOfTheFirst1000CodeUnits() throws {
        let context = try configuredSSLContext()

        for testString in (1...Int(1000)).compactMap({ UnicodeScalar($0).map({ String($0) }) }) {
            XCTAssertNoThrow(try NIOSSLClientHandler(context: context, serverHostname: testString))
            XCTAssertNoThrow(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
        }
    }

    func testSNIIsNotRejectedForVeryWeirdCharacters() throws {
        let context = try configuredSSLContext()

        let testString = "😎🥶💥🏴󠁧󠁢󠁥󠁮󠁧󠁿👩‍💻"
        XCTAssertLessThanOrEqual(testString.utf8.count, 255)  // just to check we didn't make this too large.
        XCTAssertNoThrow(try NIOSSLClientHandler(context: context, serverHostname: testString))
        XCTAssertNoThrow(try NIOSSLClientTLSProvider<ClientBootstrap>(context: context, serverHostname: testString))
    }
}
