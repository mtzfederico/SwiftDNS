//
//  EDNSExtendedError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-04
// 

import Foundation

/// The extended DNS Extended DNS Codes as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
public enum EDNSExtendedError: UInt16, Equatable, Sendable, LosslessStringConvertible {
    case otherError = 0
    case unsupportedDNSKEYAlgorithm = 1
    case unsupportedDSDigestType = 2
    case staleAnswer = 3
    case forgedAnswer = 4
    case DNSSECIndeterminate = 5
    case DNSSECBogus = 6
    case signatureExpired = 7
    case signatureNotYetValid = 8
    case DNSKEYMissing = 9
    case RRSIGMissing = 10
    case noZoneKeyBit = 11
    case NSECMissing = 12
    case cachedError = 13
    case notReady = 14
    case blocked = 15
    case censored = 16
    case filtered = 17
    case prohibited = 18
    case staleNXDomainAnswer = 19
    case notAuthoritative = 20
    case notSupported = 21
    case noReachableAuthority = 22
    case networkError = 23
    case invalidData = 24
    case signatureExpiredBeforeValid = 25
    case tooEarly = 26
    case unsupportedNSEC3IterationsValue = 27
    case unableToConformToPolicy = 28
    case synthesized = 29
    case invalidQueryType = 30
    case unknown
    
    /// Initializes an EDNS Extended Error using it's descriprion not the name.
    /// - Parameter description: The description for the EDNS Extended Error
    ///
    /// You can get the description with EDNSExtendedError.signatureExpired.description
    public init?(_ description: String) {
        switch description {
        case "Other Error":
            self = .otherError
        case "Unsupported DNSKEY Algorithm":
            self = .unsupportedDNSKEYAlgorithm
        case "Unsupported DS Digest Type" :
            self = .unsupportedDSDigestType
        case "Stale Answer":
            self = .staleAnswer
        case "Forged Answer":
            self = .forgedAnswer
        case "DNSSEC Indeterminate":
            self = .DNSSECIndeterminate
        case "DNSSEC Bogus":
            self = .DNSSECBogus
        case "Signature Expired":
            self = .signatureExpired
        case "Signature Not Yet Valid":
            self = .signatureNotYetValid
        case "DNSKEY Missing":
            self = .DNSKEYMissing
        case "RRSIGs Missing":
            self = .RRSIGMissing
        case "No Zone Key Bit Set":
            self = .noZoneKeyBit
        case "NSEC Missing":
            self = .NSECMissing
        case "Cached Error":
            self = .cachedError
        case "Not Ready":
            self = .notReady
        case "Blocked":
            self = .blocked
        case "Censored":
            self = .censored
        case "Filtered":
            self = .filtered
        case "Prohibited":
            self = .prohibited
        case "Stale NXDomain Answer":
            self = .staleNXDomainAnswer
        case "Not Authoritative":
            self = .notAuthoritative
        case "Not Supported":
            self = .notSupported
        case "No Reachable Authority":
            self = .noReachableAuthority
        case "Network Error":
            self = .networkError
        case "Invalid Data":
            self = .invalidData
        case "Signature Expired before Valid":
            self = .signatureExpiredBeforeValid
        case "Too Early":
            self = .tooEarly
        case "Unsupported NSEC3 Iterations Value":
            self = .unsupportedNSEC3IterationsValue
        case "Unable to conform to policy":
            self = .unableToConformToPolicy
        case "Synthesized":
            self = .synthesized
        case "Invalid Query Type":
            self = .invalidQueryType
        default:
            let pattern = "'(\\d+)'"
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }
            
            if let result = regex.firstMatch(in: description, options: [], range: NSRange(description.startIndex..., in: description)) {
                if let range = Range(result.range(at: 1), in: description) {
                    if let value = UInt16(description[range]) {
                        self.init(rawValue: value)
                    }
                }
            }
            return nil
        }
    }
    
    /// A short string that represents the error
    public var displayName: String {
        switch self {
        case .otherError:
            return "NoError"
        case .unsupportedDNSKEYAlgorithm:
            return "NoError"
        case .unsupportedDSDigestType:
            return "NoError"
        case .staleAnswer:
            return "NoError"
        case .forgedAnswer:
            return "NoError"
        case .DNSSECIndeterminate:
            return "NoError"
        case .DNSSECBogus:
            return "NoError"
        case .signatureExpired:
            return "NoError"
        case .signatureNotYetValid:
            return "NoError"
        case .DNSKEYMissing:
            return "NoError"
        case .RRSIGMissing:
            return "NoError"
        case .noZoneKeyBit:
            return "NoError"
        case .NSECMissing:
            return "NoError"
        case .cachedError:
            return "NoError"
        case .notReady:
            return "NoError"
        case .blocked:
            return "NoError"
        case .censored:
            return "NoError"
        case .filtered:
            return "NoError"
        case .prohibited:
            return "NoError"
        case .staleNXDomainAnswer:
            return "NoError"
        case .notAuthoritative:
            return "NoError"
        case .notSupported:
            return "NoError"
        case .noReachableAuthority:
            return "NoError"
        case .networkError:
            return "NoError"
        case .invalidData:
            return "NoError"
        case .signatureExpiredBeforeValid:
            return "NoError"
        case .tooEarly:
            return "tooEarly"
        case .unsupportedNSEC3IterationsValue:
            return "NoError"
        case .unableToConformToPolicy:
            return "NoError"
        case .synthesized:
            return "NoError"
        case .invalidQueryType:
            return "NoError"
        case .unknown:
            return "Unkown '\(rawValue)'"
        }
    }
    
    /// A short user-friendly string that describes the error
    public var description: String {
        switch self {
        case .otherError:
            return "Other Error"
        case .unsupportedDNSKEYAlgorithm:
            return "Unsupported DNSKEY Algorithm"
        case .unsupportedDSDigestType:
            return "Unsupported DS Digest Type"
        case .staleAnswer:
            return "Stale Answer"
        case .forgedAnswer:
            return "Forged Answer"
        case .DNSSECIndeterminate:
            return "DNSSEC Indeterminate"
        case .DNSSECBogus:
            return "DNSSEC Bogus"
        case .signatureExpired:
            return "Signature Expired"
        case .signatureNotYetValid:
            return "Signature Not Yet Valid"
        case .DNSKEYMissing:
            return "DNSKEY Missing"
        case .RRSIGMissing:
            return "RRSIGs Missing"
        case .noZoneKeyBit:
            return "No Zone Key Bit Set"
        case .NSECMissing:
            return "NSEC Missing"
        case .cachedError:
            return "Cached Error"
        case .notReady:
            return "Not Ready"
        case .blocked:
            return "Blocked"
        case .censored:
            return "Censored"
        case .filtered:
            return "Filtered"
        case .prohibited:
            return "Prohibited"
        case .staleNXDomainAnswer:
            return "Stale NXDomain Answer"
        case .notAuthoritative:
            return "Not Authoritative"
        case .notSupported:
            return "Not Supported"
        case .noReachableAuthority:
            return "No Reachable Authority"
        case .networkError:
            return "Network Error"
        case .invalidData:
            return "Invalid Data"
        case .signatureExpiredBeforeValid:
            return "Signature Expired before Valid"
        case .tooEarly:
            return "Too Early"
        case .unsupportedNSEC3IterationsValue:
            return "Unsupported NSEC3 Iterations Value"
        case .unableToConformToPolicy:
            return "Unable to conform to policy"
        case .synthesized:
            return "Synthesized"
        case .invalidQueryType:
            return "Invalid Query Type"
        case .unknown:
            return "unknown. Value: '\(rawValue)'"
        }
    }
    
    public static func ==(lhs: EDNSExtendedError, rhs: EDNSExtendedError) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
