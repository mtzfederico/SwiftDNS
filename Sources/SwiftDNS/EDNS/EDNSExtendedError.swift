//
//  EDNSExtendedError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-04
// 

import Foundation

/// The extended DNS Extended DNS Codes as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
public enum EDNSExtendedError: Equatable, Sendable, LosslessStringConvertible, CustomDebugStringConvertible, CaseIterable {
    public static let allCases: [EDNSExtendedError] = [.otherError, .unsupportedDNSKEYAlgorithm, .unsupportedDSDigestType, .staleAnswer, .forgedAnswer, .DNSSECIndeterminate, .DNSSECBogus, .signatureExpired, .signatureNotYetValid, .DNSKEYMissing, .RRSIGMissing, .noZoneKeyBit, .NSECMissing, .cachedError, .notReady, .blocked, .censored, .filtered, .prohibited, .staleNXDomainAnswer, .notAuthoritative, .notSupported, .noReachableAuthority, .networkError, .invalidData, .signatureExpiredBeforeValid, .tooEarly, .unsupportedNSEC3IterationsValue, .unableToConformToPolicy, .synthesized, .invalidQueryType]
    
    case otherError // = 0
    case unsupportedDNSKEYAlgorithm // = 1
    case unsupportedDSDigestType // = 2
    case staleAnswer // = 3
    case forgedAnswer // = 4
    case DNSSECIndeterminate // = 5
    case DNSSECBogus // = 6
    case signatureExpired // = 7
    case signatureNotYetValid // = 8
    case DNSKEYMissing // = 9
    case RRSIGMissing // = 10
    case noZoneKeyBit // = 11
    case NSECMissing // = 12
    case cachedError // = 13
    case notReady // = 14
    case blocked // = 15
    case censored // = 16
    case filtered // = 17
    case prohibited // = 18
    case staleNXDomainAnswer // = 19
    case notAuthoritative // = 20
    case notSupported // = 21
    case noReachableAuthority // = 22
    case networkError//  = 23
    case invalidData // = 24
    case signatureExpiredBeforeValid // = 25
    case tooEarly // = 26
    case unsupportedNSEC3IterationsValue // = 27
    case unableToConformToPolicy // = 28
    case synthesized // = 29
    case invalidQueryType // = 30
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 0:
            self = .otherError
        case 1:
            self = .unsupportedDNSKEYAlgorithm
        case 2:
            self = .unsupportedDSDigestType
        case 3:
            self = .staleAnswer
        case 4:
            self = .forgedAnswer
        case 5:
            self = .DNSSECIndeterminate
        case 6:
            self = .DNSSECBogus
        case 7:
            self = .signatureExpired
        case 8:
            self = .signatureNotYetValid
        case 9:
            self = .DNSKEYMissing
        case 10:
            self = .RRSIGMissing
        case 11:
            self = .noZoneKeyBit
        case 12:
            self = .NSECMissing
        case 13:
            self = .cachedError
        case 14:
            self = .notReady
        case 15:
            self = .blocked
        case 16:
            self = .censored
        case 17:
            self = .filtered
        case 18:
            self = .prohibited
        case 19:
            self = .staleNXDomainAnswer
        case 20:
            self = .notAuthoritative
        case 21:
            self = .notSupported
        case 22:
            self = .noReachableAuthority
        case 23:
            self = .networkError
        case 24:
            self = .invalidData
        case 25:
            self = .signatureExpiredBeforeValid
        case 26:
            self = .tooEarly
        case 27:
            self = .unsupportedNSEC3IterationsValue
        case 28:
            self = .unableToConformToPolicy
        case 29:
            self = .synthesized
        case 30:
            self = .invalidQueryType
        default:
            self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .otherError:
            return 0
        case .unsupportedDNSKEYAlgorithm:
            return 1
        case .unsupportedDSDigestType:
            return 2
        case .staleAnswer:
            return 3
        case .forgedAnswer:
            return 4
        case .DNSSECIndeterminate:
            return 5
        case .DNSSECBogus:
            return 6
        case .signatureExpired:
            return 7
        case .signatureNotYetValid:
            return 8
        case .DNSKEYMissing:
            return 9
        case .RRSIGMissing:
            return 10
        case .noZoneKeyBit:
            return 11
        case .NSECMissing:
            return 12
        case .cachedError:
            return 13
        case .notReady:
            return 14
        case .blocked:
            return 15
        case .censored:
            return 16
        case .filtered:
            return 17
        case .prohibited:
            return 18
        case .staleNXDomainAnswer:
            return 19
        case .notAuthoritative:
            return 20
        case .notSupported:
            return 21
        case .noReachableAuthority:
            return 22
        case .networkError:
            return 23
        case .invalidData:
            return 24
        case .signatureExpiredBeforeValid:
            return 25
        case .tooEarly:
            return 26
        case .unsupportedNSEC3IterationsValue:
            return 27
        case .unableToConformToPolicy:
            return 28
        case .synthesized:
            return 29
        case .invalidQueryType:
            return 30
        case .unknown(let value):
            return value
        }
    }
    
    /// Initializes an EDNS Extended Error using it's descriprion
    /// - Parameter description: The description for the EDNS Extended Error
    ///
    /// You can get the description with EDNSExtendedError.signatureExpired.description
    public init?(_ description: String) {
        switch description {
        case "otherError":
            self = .otherError
        case "unsupportedDNSKEYAlgorithm":
            self = .unsupportedDNSKEYAlgorithm
        case "unsupportedDSDigestType" :
            self = .unsupportedDSDigestType
        case "staleAnswer":
            self = .staleAnswer
        case "forgedAnswer":
            self = .forgedAnswer
        case "DNSSECIndeterminate":
            self = .DNSSECIndeterminate
        case "DNSSECBogus":
            self = .DNSSECBogus
        case "signatureExpired":
            self = .signatureExpired
        case "signatureNotYetValid":
            self = .signatureNotYetValid
        case "DNSKEYMissing":
            self = .DNSKEYMissing
        case "RRSIGMissing":
            self = .RRSIGMissing
        case "noZoneKeyBit":
            self = .noZoneKeyBit
        case "NSECMissing":
            self = .NSECMissing
        case "cachedError":
            self = .cachedError
        case "notReady":
            self = .notReady
        case "blocked":
            self = .blocked
        case "censored":
            self = .censored
        case "filtered":
            self = .filtered
        case "prohibited":
            self = .prohibited
        case "staleNXDomainAnswer":
            self = .staleNXDomainAnswer
        case "notAuthoritative":
            self = .notAuthoritative
        case "notSupported":
            self = .notSupported
        case "noReachableAuthority":
            self = .noReachableAuthority
        case "networkError":
            self = .networkError
        case "invalidData":
            self = .invalidData
        case "signatureExpiredBeforeValid":
            self = .signatureExpiredBeforeValid
        case "tooEarly":
            self = .tooEarly
        case "unsupportedNSEC3IterationsValue":
            self = .unsupportedNSEC3IterationsValue
        case "unableToConformToPolicy":
            self = .unableToConformToPolicy
        case "synthesized":
            self = .synthesized
        case "invalidQueryType":
            self = .invalidQueryType
        default:
            // Limit to 5 digits since a UInt16 is limited to 65535
            let pattern = #"^ExtendedError(\d{1,5})$"#
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }
            
            if let result = regex.firstMatch(in: description, options: [], range: NSRange(description.startIndex..., in: description)) {
                if let range = Range(result.range(at: 1), in: description) {
                    if let value = UInt16(description[range]) {
                        self.init(value)
                        return
                    }
                }
            }
            return nil
        }
    }
    
    /// A short string that represents the error
    ///
    /// Returns the string used in the string initializer
    public var description: String {
        switch self {
        case .otherError:
            return "otherError"
        case .unsupportedDNSKEYAlgorithm:
            return "unsupportedDNSKEYAlgorithm"
        case .unsupportedDSDigestType:
            return "unsupportedDSDigestType"
        case .staleAnswer:
            return "staleAnswer"
        case .forgedAnswer:
            return "forgedAnswer"
        case .DNSSECIndeterminate:
            return "DNSSECIndeterminate"
        case .DNSSECBogus:
            return "DNSSECBogus"
        case .signatureExpired:
            return "signatureExpired"
        case .signatureNotYetValid:
            return "signatureNotYetValid"
        case .DNSKEYMissing:
            return "DNSKEYMissing"
        case .RRSIGMissing:
            return "RRSIGMissing"
        case .noZoneKeyBit:
            return "noZoneKeyBit"
        case .NSECMissing:
            return "NSECMissing"
        case .cachedError:
            return "cachedError"
        case .notReady:
            return "notReady"
        case .blocked:
            return "blocked"
        case .censored:
            return "censored"
        case .filtered:
            return "filtered"
        case .prohibited:
            return "prohibited"
        case .staleNXDomainAnswer:
            return "staleNXDomainAnswer"
        case .notAuthoritative:
            return "notAuthoritative"
        case .notSupported:
            return "notSupported"
        case .noReachableAuthority:
            return "noReachableAuthority"
        case .networkError:
            return "networkError"
        case .invalidData:
            return "invalidData"
        case .signatureExpiredBeforeValid:
            return "signatureExpiredBeforeValid"
        case .tooEarly:
            return "tooEarly"
        case .unsupportedNSEC3IterationsValue:
            return "unsupportedNSEC3IterationsValue"
        case .unableToConformToPolicy:
            return "unableToConformToPolicy"
        case .synthesized:
            return "synthesized"
        case .invalidQueryType:
            return "invalidQueryType"
        case .unknown(let value):
            return "ExtendedError\(value)"
        }
    }
    
    /// A short user-friendly string that describes the error
    public var debugDescription: String {
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
        case .unknown(let value):
            return "Unkown '\(value)'"
        }
    }
    
    public static func ==(lhs: EDNSExtendedError, rhs: EDNSExtendedError) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
