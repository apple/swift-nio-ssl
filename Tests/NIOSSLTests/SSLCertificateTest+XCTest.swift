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
//
// SSLCertificateTest+XCTest.swift
//
import XCTest

///
/// NOTE: This file was generated by generate_linux_tests.rb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

extension SSLCertificateTest {

   @available(*, deprecated, message: "not actually deprecated. Just deprecated to allow deprecated tests (which test deprecated functionality) without warnings")
   static var allTests : [(String, (SSLCertificateTest) -> () throws -> Void)] {
      return [
                ("testLoadingPemCertFromFile", testLoadingPemCertFromFile),
                ("testLoadingDerCertFromFile", testLoadingDerCertFromFile),
                ("testDerAndPemAreIdentical", testDerAndPemAreIdentical),
                ("testLoadingPemCertFromMemory", testLoadingPemCertFromMemory),
                ("testPemLoadingMechanismsAreIdentical", testPemLoadingMechanismsAreIdentical),
                ("testLoadingPemCertsFromMemory", testLoadingPemCertsFromMemory),
                ("testLoadingPemCertsFromFile", testLoadingPemCertsFromFile),
                ("testLoadingDerCertFromMemory", testLoadingDerCertFromMemory),
                ("testLoadingGibberishFromMemoryAsPemFails", testLoadingGibberishFromMemoryAsPemFails),
                ("testLoadingGibberishFromPEMBufferFails", testLoadingGibberishFromPEMBufferFails),
                ("testLoadingGibberishFromMemoryAsDerFails", testLoadingGibberishFromMemoryAsDerFails),
                ("testLoadingGibberishFromFileAsPemFails", testLoadingGibberishFromFileAsPemFails),
                ("testLoadingGibberishFromPEMFileFails", testLoadingGibberishFromPEMFileFails),
                ("testLoadingGibberishFromFileAsDerFails", testLoadingGibberishFromFileAsDerFails),
                ("testLoadingNonexistentFileAsPem", testLoadingNonexistentFileAsPem),
                ("testLoadingNonexistentPEMFile", testLoadingNonexistentPEMFile),
                ("testLoadingNonexistentFileAsDer", testLoadingNonexistentFileAsDer),
                ("testEnumeratingSanFields", testEnumeratingSanFields),
                ("testNonexistentSan", testNonexistentSan),
                ("testCommonName", testCommonName),
                ("testCommonNameForGeneratedCert", testCommonNameForGeneratedCert),
                ("testMultipleCommonNames", testMultipleCommonNames),
                ("testNoCommonName", testNoCommonName),
                ("testUnicodeCommonName", testUnicodeCommonName),
                ("testExtractingPublicKey", testExtractingPublicKey),
           ]
   }
}

