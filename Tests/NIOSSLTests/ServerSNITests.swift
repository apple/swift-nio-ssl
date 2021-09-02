//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
import NIO
import NIOTLS
import NIOSSL


class ServerSNITests: XCTestCase {
    
    class SniServerContext {
    
        private var _tlsConfig : TLSConfiguration?;
        
        private var _ctx : NIOSSLContext?
        
        private(set) var SniExpectation : XCTestExpectation
        
        public var SSLContext : NIOSSLContext
        {
            get
            {
                return _ctx!
            }
        }
        
        private var _indicatedHostname : String?
        
        public var IndicatedHostname : String
        {
            get
            {
                return _indicatedHostname!
            }
        }
        
        private init(sniExpectation: XCTestExpectation) {
            SniExpectation = sniExpectation
        }
     
        private func sniCallback (host: String, ctx: NIOSSLContext) -> NIOSSLContext? {
            self._indicatedHostname = host
            self.SniExpectation.fulfill()
            return ctx
        }
        
        public static func Create(sniExpectation: XCTestExpectation) -> SniServerContext {
            let serverCtx = SniServerContext(sniExpectation: sniExpectation)
            
            serverCtx._indicatedHostname = String()
            serverCtx._tlsConfig = TLSConfiguration.makeServerConfiguration(sniCallback: serverCtx.sniCallback)
            serverCtx._ctx = try! NIOSSLContext(configuration: serverCtx._tlsConfig!)
            
            return serverCtx
        }
    }
    
    static var cert: NIOSSLCertificate!
    static var key: NIOSSLPrivateKey!

    override class func setUp() {
        super.setUp()
        let (cert, key) = generateSelfSignedCert()
        NIOSSLIntegrationTest.cert = cert
        NIOSSLIntegrationTest.key = key
    }

    private func configuredClientSSLContext() throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(NIOSSLIntegrationTest.cert)],
            privateKey: .privateKey(NIOSSLIntegrationTest.key)
        )
        config.trustRoots = .certificates([NIOSSLIntegrationTest.cert])
        let context = try NIOSSLContext(configuration: config)
        return context
    }
    
    private func configuredServerSSLContext() throws -> SniServerContext {
        let expectation = expectation(description: "Notification Raised")
        return SniServerContext.Create(sniExpectation: expectation)
    }

    private func assertSniResult(sniField: String?, expectedResult: String) throws {
        let clientContext = try configuredClientSSLContext()

        let serverContext = try configuredServerSSLContext()
        
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer {
            try? group.syncShutdownGracefully()
        }
       
        let serverChannel = try serverTLSChannel(context: serverContext.SSLContext, preHandlers: [], postHandlers: [], group: group)
        
        defer {
            _ = try? serverChannel.close().wait()
        }

        let clientChannel = try clientTLSChannel(context: clientContext,
                                                 preHandlers: [],
                                                 postHandlers: [],
                                                 group: group,
                                                 connectingTo: serverChannel.localAddress!,
                                                 serverHostname: sniField)
        defer {
            _ = try? clientChannel.close().wait()
        }
        
        let result = XCTWaiter.wait(for: [serverContext.SniExpectation], timeout: 3.0)
         if result == XCTWaiter.Result.timedOut {
            // Don't raise an exception on timeout when we expect not to
            // get a result. There are test cases where we actually
            // want to succeed if the SNI callback is never called.
            if !expectedResult.isEmpty {
                XCTFail("Timed out while awaiting expected SNI callback value.")
            }
         }
        
        let sniResult = serverContext.IndicatedHostname
        
        XCTAssertEqual(sniResult, expectedResult)
    }

    func testSNIIsTransmitted() throws {
        try assertSniResult(sniField: "httpbin.org", expectedResult: "httpbin.org")
    }

    func testNoSNILeadsToNoSNI() throws {
        try assertSniResult(sniField: nil, expectedResult: String())
    }

    func testSNIIsNotRejectedForAnyOfTheFirst1000CodeUnits() throws {
        for testString in (1...Int(1000)).compactMap({ UnicodeScalar($0).map { String($0) } }) {
            try assertSniResult(sniField: testString, expectedResult:testString)
        }
    }

    func testSNIIsNotRejectedForVeryWeirdCharacters() throws {
        let testString = "😎🥶💥🏴󠁧󠁢󠁥󠁮󠁧󠁿👩‍💻"
        try assertSniResult(sniField: testString, expectedResult: testString)
    }
}
