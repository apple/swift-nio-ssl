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
import XCTest

@_implementationOnly import CNIOBoringSSL
@_implementationOnly import CNIOBoringSSLShims

@testable import NIOSSL

final class CustomVerifyManagerTests: XCTestCase {
    private let unchangedAlert: UInt8 = 0xA5
    // TLS AlertDescription.bad_certificate's wire value (RFC 5246 section 7.2).
    private let tlsBadCertificateAlert: UInt8 = 42

    private func makeConnection() throws -> (SSLConnection, EmbeddedEventLoop) {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates([])
        let context = try NIOSSLContext(configuration: configuration)
        let connection = context.createConnection()!
        let eventLoop = EmbeddedEventLoop()
        connection.eventLoop = eventLoop
        return (connection, eventLoop)
    }

    private func process(
        _ manager: CustomVerifyManager,
        runEventLoop: Bool = true
    ) throws -> (first: ssl_verify_result_t, second: ssl_verify_result_t?, alert: UInt8) {
        let (connection, eventLoop) = try self.makeConnection()
        connection.customVerificationManager = manager

        var alert = self.unchangedAlert
        let first = connection.customVerificationManager!.process(on: connection, outAlert: &alert)

        guard runEventLoop else {
            return (first, nil, alert)
        }

        eventLoop.run()
        let second = connection.customVerificationManager!.process(on: connection, outAlert: &alert)
        return (first, second, alert)
    }

    func testInternalFailureWritesConfiguredAlert() throws {
        let expectedAlert = CNIOBoringSSLShims_SSL_AD_BAD_CERTIFICATE()
        let manager = CustomVerifyManager(
            callback: { promise in promise.succeed(.failed) },
            failureAlert: expectedAlert
        )

        let result = try self.process(manager)

        XCTAssertEqual(expectedAlert, self.tlsBadCertificateAlert)
        XCTAssertEqual(result.first, ssl_verify_retry)
        XCTAssertEqual(result.second, ssl_verify_invalid)
        XCTAssertEqual(result.alert, expectedAlert)
    }

    func testPublicFailureLeavesAlertUnspecified() throws {
        let callback: NIOSSLCustomVerificationCallback = { _, promise in
            promise.succeed(.failed)
        }
        let manager = CustomVerifyManager(callback: callback)

        let result = try self.process(manager)

        XCTAssertEqual(result.first, ssl_verify_retry)
        XCTAssertEqual(result.second, ssl_verify_invalid)
        XCTAssertEqual(result.alert, self.unchangedAlert)
    }

    func testPublicMetadataFailureLeavesAlertUnspecified() throws {
        let callback: NIOSSLCustomVerificationCallbackWithMetadata = { _, promise in
            promise.succeed(.failed)
        }
        let manager = CustomVerifyManager(callback: callback)

        let result = try self.process(manager)

        XCTAssertEqual(result.first, ssl_verify_retry)
        XCTAssertEqual(result.second, ssl_verify_invalid)
        XCTAssertEqual(result.alert, self.unchangedAlert)
    }

    func testInternalSuccessLeavesAlertUnchanged() throws {
        let manager = CustomVerifyManager(
            callback: { promise in promise.succeed(.certificateVerified) },
            failureAlert: CNIOBoringSSLShims_SSL_AD_BAD_CERTIFICATE()
        )

        let result = try self.process(manager)

        XCTAssertEqual(result.first, ssl_verify_retry)
        XCTAssertEqual(result.second, ssl_verify_ok)
        XCTAssertEqual(result.alert, self.unchangedAlert)
    }

    func testPendingInternalVerificationLeavesAlertUnchanged() throws {
        let manager = CustomVerifyManager(
            callback: { _ in },
            failureAlert: CNIOBoringSSLShims_SSL_AD_BAD_CERTIFICATE()
        )

        let result = try self.process(manager, runEventLoop: false)

        XCTAssertEqual(result.first, ssl_verify_retry)
        XCTAssertNil(result.second)
        XCTAssertEqual(result.alert, self.unchangedAlert)
    }

    func testDarwinDefaultTrustManagerUsesBadCertificateAlert() throws {
        #if canImport(Darwin)
        let context = try NIOSSLContext(configuration: .makeClientConfiguration())
        let connection = context.createConnection()!

        XCTAssertEqual(
            connection.customVerificationManager?.failureAlert,
            CNIOBoringSSLShims_SSL_AD_BAD_CERTIFICATE()
        )
        #endif
    }
}
