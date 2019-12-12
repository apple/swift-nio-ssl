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

import NIO


private let asciiIDNAIdentifier: ArraySlice<UInt8> = Array("xn--".utf8)[...]
private let asciiCapitals: ClosedRange<UInt8> = (UInt8(ascii: "A")...UInt8(ascii: "Z"))
private let asciiLowercase: ClosedRange<UInt8> = (UInt8(ascii: "a")...UInt8(ascii: "z"))
private let asciiNumbers: ClosedRange<UInt8> = (UInt8(ascii: "0")...UInt8(ascii: "9"))
private let asciiHyphen: UInt8 = UInt8(ascii: "-")
private let asciiPeriod: UInt8 = UInt8(ascii: ".")
private let asciiAsterisk: UInt8 = UInt8(ascii: "*")


extension String {
    /// Calls `fn` with an `Array<UInt8>` pointing to a
    /// non-NULL-terminated sequence of ASCII bytes. If the string this method
    /// is called on contains non-ACSII code points, this method throws.
    ///
    /// This method exists to avoid doing repeated loops over the string buffer.
    /// In a naive implementation we'd loop at least three times: once to lowercase
    /// the string, once to get a buffer pointer to a contiguous buffer, and once
    /// to confirm the string is ASCII. Here we can do that all in one loop.
    fileprivate func withLowercaseASCIIBuffer<T>(_ fn: (Array<UInt8>) throws -> T) throws -> T {
        let buffer: [UInt8] = try self.utf8.map { codeUnit in
            guard codeUnit.isValidDNSCharacter else {
                throw NIOSSLExtraError.serverHostnameImpossibleToMatch(hostname: self)
            }

            // We know we have only ASCII printables, we can safely unconditionally set the 6 bit to 1 to lowercase.
            return codeUnit | (0x20)
        }

        return try fn(buffer)
    }
}


extension Collection {
    /// Splits a collection in two around a given index. This index may be nil, in which case the split
    /// will occur around the end.
    fileprivate func splitAroundIndex(_ index: Index?) -> (SubSequence, SubSequence) {
        guard let index = index else {
            return (self[...], self[self.endIndex...])
        }

        let subsequentIndex = self.index(after: index)
        return (self[..<index], self[subsequentIndex...])
    }
}


extension UInt8 {
    /// Whether this character is a valid DNS character, which is the ASCII
    /// letters, digits, the hypen, and the period.
    fileprivate var isValidDNSCharacter: Bool {
        switch self {
        case asciiCapitals, asciiLowercase, asciiNumbers, asciiHyphen, asciiPeriod:
            return true
        default:
            return false
        }
    }
}


/// Validates that a given leaf certificate is valid for a service.
///
/// This function implements the logic for service validation as specified by
/// RFC 6125 (https://tools.ietf.org/search/rfc6125), which loosely speaking
/// defines the common algorithm used for validating that an X.509 certificate
/// is valid for a given service
///
/// The algorithm we're implementing is specified in RFC 6125 Section 6 if you want to
/// follow along at home.
internal func validIdentityForService(serverHostname: String?,
                                      socketAddress: SocketAddress,
                                      leafCertificate: NIOSSLCertificate) throws -> Bool {
    if let serverHostname = serverHostname {
        return try serverHostname.withLowercaseASCIIBuffer {
            try validIdentityForService(serverHostname: $0,
                                        socketAddress: socketAddress,
                                        leafCertificate: leafCertificate)
        }
    } else {
        return try validIdentityForService(serverHostname: nil as Array<UInt8>?,
                                           socketAddress: socketAddress,
                                           leafCertificate: leafCertificate)
    }
}

private func validIdentityForService(serverHostname: Array<UInt8>?,
                                     socketAddress: SocketAddress,
                                     leafCertificate: NIOSSLCertificate) throws -> Bool {
    // Before we begin, we want to locate the first period in our own domain name. We need to do
    // this because we may need to match a wildcard label.
    var serverHostnameSlice: ArraySlice<UInt8>? = nil
    var firstPeriodIndex: ArraySlice<UInt8>.Index? = nil

    if let serverHostname = serverHostname {
        var tempServerHostnameSlice = serverHostname[...]


        // Strip trailing period
        if tempServerHostnameSlice.last == .some(asciiPeriod) {
            tempServerHostnameSlice = tempServerHostnameSlice.dropLast()
        }

        firstPeriodIndex = tempServerHostnameSlice.firstIndex(of: asciiPeriod)
        serverHostnameSlice = tempServerHostnameSlice
    }

    // We want to begin by checking the subjectAlternativeName fields. If there are any fields
    // in there that we could validate against (either IP or hostname) we will validate against
    // them, and then refuse to check the commonName field. If there are no SAN fields to
    // validate against, we'll check commonName.
    var checkedMatch = false
    if let alternativeNames = leafCertificate.subjectAlternativeNames() {
        for name in alternativeNames {
            checkedMatch = true

            switch name {
            case .dnsName(let dnsName):
                if matchHostname(ourHostname: serverHostnameSlice, firstPeriodIndex: firstPeriodIndex, dnsName: dnsName) {
                    return true
                }
            case .ipAddress(let ip):
                if matchIpAddress(socketAddress: socketAddress, certificateIP: ip) {
                    return true
                }
            }
        }
    }

    guard !checkedMatch else {
        // We had some subject alternative names, but none matched. We failed here.
        return false
    }

    // In the absence of any matchable subjectAlternativeNames, we can fall back to checking
    // the common name. This is a deprecated practice, and in a future release we should
    // stop doing this.
    guard let commonName = leafCertificate.commonName() else {
        // No CN, no match.
        return false
    }

    // We have a common name. Let's check it against the provided hostname. We never check
    // the common name against the IP address.
    return matchHostname(ourHostname: serverHostnameSlice, firstPeriodIndex: firstPeriodIndex, dnsName: commonName)
}


private func matchHostname(ourHostname: ArraySlice<UInt8>?, firstPeriodIndex: ArraySlice<UInt8>.Index?, dnsName: Array<UInt8>) -> Bool {
    guard let ourHostname = ourHostname else {
        // No server hostname was provided, so we cannot match.
        return false
    }

    // Now we validate the cert hostname.
    var dnsName = ArraySlice(dnsName)
    guard let validatedHostname = AnalysedCertificateHostname(baseName: &dnsName) else {
        // This is a hostname we can't match, return false.
        return false
    }
    return validatedHostname.validMatchForName(ourHostname, firstPeriodIndexForName: firstPeriodIndex)
}


private func matchIpAddress(socketAddress: SocketAddress, certificateIP: NIOSSLCertificate.IPAddress) -> Bool {
    // These match if the two underlying IP address structures match.
    switch (socketAddress, certificateIP) {
    case (.v4(let address), .ipv4(var addr2)):
        var addr1 = address.address.sin_addr
        return memcmp(&addr1, &addr2, MemoryLayout<in_addr>.size) == 0
    case (.v6(let address), .ipv6(var addr2)):
        var addr1 = address.address.sin6_addr
        return memcmp(&addr1, &addr2, MemoryLayout<in6_addr>.size) == 0
    default:
        // Different protocol families, no match.
        return false
    }
}


/// This structure contains a certificate hostname that has been analysed and prepared for matching.
///
/// A certificate hostname that is valid for matching meets the following criteria:
///
/// 1. Contains only valid DNS characters, plus the ASCII asterisk.
/// 2. Contains zero or one ASCII asterisks.
/// 3. Any ASCII asterisk present must be in the first DNS label (i.e. before the first period).
/// 4. If the first label contains an ASCII asterisk, it must not also be an IDN A label.
///
/// Answering these questions potentially relies on multiple searches through the hostname. That's not
/// ideal: it'd be better to do a single search that both validates the domain name meets the criteria
/// and that also records information needed to validate that the name matches the one we're searching for.
/// That's what this structure does.
fileprivate struct AnalysedCertificateHostname {
    /// The type we use to store the base name. The other types on this object are chosen relative to that.
    fileprivate typealias BaseNameType = ArraySlice<UInt8>

    private var name: NameType

    fileprivate init?(baseName: inout BaseNameType) {
        // First, strip a trailing period from this name.
        if baseName.last == .some(asciiPeriod) {
            baseName = baseName.dropLast()
        }

        // Ok, start looping.
        var index = baseName.startIndex
        var firstPeriodIndex: Optional<BaseNameType.Index> = nil
        var asteriskIndex: Optional<BaseNameType.Index> = nil

        while index < baseName.endIndex {
            switch baseName[index] {
            case asciiPeriod where firstPeriodIndex == nil:
                // This is the first period we've seen, great. Future
                // periods will be ignored.
                firstPeriodIndex = index

            case asciiCapitals, asciiLowercase, asciiNumbers, asciiHyphen, asciiPeriod:
                // Valid character, no notes.
                break

            case asciiAsterisk where asteriskIndex == nil && firstPeriodIndex == nil:
                // Found an asterisk, it's the first one, and it precedes any periods.
                asteriskIndex = index

            case asciiAsterisk:
                // An extra asterisk, or an asterisk after a period, is unacceptable.
                return nil

            default:
                // Unacceptable character in the name.
                return nil
            }

            baseName.formIndex(after: &index)
        }

        // Now we can finally initialize ourself.
        if let asteriskIndex = asteriskIndex {
            // One final check: if we found a wildcard, we need to confirm that the first label isn't an IDNA A label.
            guard baseName.prefix(4) != asciiIDNAIdentifier else {
                return nil
            }

            self.name = .wildcard(baseName, asteriskIndex: asteriskIndex, firstPeriodIndex: firstPeriodIndex)
        } else {
            self.name = .singleName(baseName)
        }
    }

    /// Whether this parsed name is a valid match for the one passed in.
    fileprivate func validMatchForName(_ target: BaseNameType, firstPeriodIndexForName: BaseNameType.Index?) -> Bool {
        switch self.name {
        case .singleName(let baseName):
            // For non-wildcard names, we just do a straightforward string comparison.
            return baseName == target

        case .wildcard(let baseName, asteriskIndex: let asteriskIndex, firstPeriodIndex: let firstPeriodIndex):
            // The wildcard can appear more-or-less anywhere in the first label. The wildcard
            // character itself can match any number of characters, though it must match at least
            // one.
            // The algorithm for this is simple: first, we split the two names on their first period to get their
            // first label and their subsequent components. Second, we check that the subcomponents match a straightforward
            // bytewise comparison: if that fails, we can avoid the expensive wildcard checking operation.
            // Third, we split the wildcard label on the wildcard character, and and confirm that
            // the characters *before* the wildcard are the prefix of the target first label, and that the
            // characters *after* the wildcard are the suffix of the target first label. This works well because
            // the empty string is a prefix and suffix of all strings.
            let (wildcardLabel, remainingComponents) = baseName.splitAroundIndex(firstPeriodIndex)
            let (targetFirstLabel, targetRemainingComponents) = target.splitAroundIndex(firstPeriodIndexForName)

            guard remainingComponents == targetRemainingComponents else {
                // Wildcard is irrelevant, the remaining components don't match.
                return false
            }

            guard targetFirstLabel.count >= wildcardLabel.count else {
                // The target label cannot possibly match the wildcard.
                return false
            }

            let (wildcardLabelPrefix, wildcardLabelSuffix) = wildcardLabel.splitAroundIndex(asteriskIndex)

            return (targetFirstLabel.prefix(wildcardLabelPrefix.count) == wildcardLabelPrefix &&
                    targetFirstLabel.suffix(wildcardLabelSuffix.count) == wildcardLabelSuffix)
        }
    }
}


extension AnalysedCertificateHostname {
    private enum NameType {
        case wildcard(BaseNameType, asteriskIndex: BaseNameType.Index, firstPeriodIndex: Optional<BaseNameType.Index>)
        case singleName(BaseNameType)
    }
}

