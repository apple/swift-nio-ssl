//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL

/// Defines the type of X509 name
public struct SSLCertificateNameType: Equatable, Hashable, Sendable {
    internal var nid: Int32
    public static let organization = SSLCertificateNameType(nid: NID_organizationName)
    public static let organizationalUnit = SSLCertificateNameType(nid: NID_organizationalUnitName)
    public static let state = SSLCertificateNameType(nid: NID_stateOrProvinceName)
    public static let country = SSLCertificateNameType(nid: NID_countryName)
    public static let city = SSLCertificateNameType(nid: NID_localityName)
    public static let commonName = SSLCertificateNameType(nid: NID_commonName)
    public static let emailAddress = SSLCertificateNameType(nid: NID_pkcs9_emailAddress)
    public static let userId = SSLCertificateNameType(nid: NID_userId)
}

/// Contains the string value of a X509 name
public struct SSLCertificateName: Equatable, Hashable, Sendable {
    public var value: String
    public var type: SSLCertificateNameType

    public init(_ value: String, _ type: SSLCertificateNameType) {
        self.value = value
        self.type = type
    }
}

extension NIOSSLCertificate {
    private static func convertName(_ name: OpaquePointer) -> [SSLCertificateName] {

        let count = CNIOBoringSSL_X509_NAME_entry_count(name)
        var names = [SSLCertificateName]()
        names.reserveCapacity(Int(count))
        for index in 0..<count {
            guard let entry = CNIOBoringSSL_X509_NAME_get_entry(name, index) else {
                continue
            }

            guard let object = CNIOBoringSSL_X509_NAME_ENTRY_get_object(entry) else {
                continue
            }

            guard let data = CNIOBoringSSL_X509_NAME_ENTRY_get_data(entry) else {
                continue
            }

            var encodedName: UnsafeMutablePointer<UInt8>? = nil
            let stringLength = CNIOBoringSSL_ASN1_STRING_to_UTF8(&encodedName, data)

            guard let namePtr = encodedName else {
                continue
            }

            defer {
                CNIOBoringSSL_OPENSSL_free(namePtr)
            }

            let arr = UnsafeBufferPointer(start: namePtr, count: Int(stringLength))
            let nameString = String(decoding: arr, as: UTF8.self)
            let nid = CNIOBoringSSL_OBJ_obj2nid(object)
            names.append(SSLCertificateName(nameString, .init(nid: nid)))
        }

        return names
    }

    /// Return an array of SSLCertificateName enums containing the subject name of the
    /// underlying X509 Certificate
    public var subjectName: [SSLCertificateName] {
        guard let subjectName = CNIOBoringSSL_X509_get_subject_name(self._ref) else {
            return []
        }

        return Self.convertName(subjectName)

    }

    /// Return an array of SSLCertificateName enums containing the issuer name of the
    /// underlying X509 Certificate
    public var issuerName: [SSLCertificateName] {
        guard let issuerName = CNIOBoringSSL_X509_get_issuer_name(self._ref) else {
            return []
        }

        return Self.convertName(issuerName)
    }
}
