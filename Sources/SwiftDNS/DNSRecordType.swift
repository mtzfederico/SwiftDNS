//
//  DNSRecordType.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// DNS record type
///
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
public enum DNSRecordType: Equatable, LosslessStringConvertible, Sendable, CaseIterable, Hashable {
    public static let allCases: [DNSRecordType] = [ .A, .NS, .CNAME, .SOA, .PTR, .MX, .TXT, .AAAA, .SRV, .DNAME, .OPT, .DS, .SSHFP, .RRSIG, .NSEC, .DNSKEY, .NSEC3, .SVCB, .HTTPS, .IXFR, .AXFR, .ANY]
    
    case A // = 1
    case NS // = 2
    case CNAME // = 5
    case SOA // = 6
    case PTR // = 12
    case MX // = 15
    case TXT // = 16
    case AAAA // = 28
    // https://www.rfc-editor.org/rfc/rfc2782.html
    case SRV // = 33
    // https://www.rfc-editor.org/rfc/rfc6672
    case DNAME // = 39
    // https://www.rfc-editor.org/rfc/rfc6891
    case OPT // = 41
    // https://www.rfc-editor.org/rfc/rfc4034.html#section-5
    case DS // = 43
    // https://www.rfc-editor.org/rfc/rfc4255.html
    case SSHFP // = 44
    // https://www.rfc-editor.org/rfc/rfc4034.html#section-3
    case RRSIG // = 46
    // https://www.rfc-editor.org/rfc/rfc4034.html#section-4
    case NSEC // = 47
    // https://www.rfc-editor.org/rfc/rfc4034.html#section-2
    case DNSKEY // = 48
    case NSEC3 // = 50
    // https://www.rfc-editor.org/rfc/rfc9460.html#section-2
    case SVCB // = 64
    // https://www.rfc-editor.org/rfc/rfc9460.html#section-9.1
    case HTTPS // = 65
    case IXFR // = 251
    case AXFR // = 252
    case ANY // = 255
    // https://datatracker.ietf.org/doc/html/rfc3597
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 1: self = .A
        case 2: self = .NS
        case 5: self = .CNAME
        case 6: self = .SOA
        case 12: self = .PTR
        case 15: self = .MX
        case 16: self = .TXT
        case 28: self = .AAAA
        case 33: self = .SRV
        case 39: self = .DNAME
        case 41: self = .OPT
        case 43: self = .DS
        case 44: self = .SSHFP
        case 46: self = .RRSIG
        case 47: self = .NSEC
        case 48: self = .DNSKEY
        case 50: self = .NSEC3
        case 64: self = .SVCB
        case 65: self = .HTTPS
        case 251: self = .IXFR
        case 252: self = .AXFR
        case 255: self = .ANY
        default: self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .A: return 1
        case .NS: return 2
        case .CNAME: return 5
        case .SOA: return 6
        case .PTR: return 12
        case .MX: return 15
        case .TXT: return 16
        case .AAAA: return 28
        case .SRV: return 33
        case .DNAME: return 39
        case .OPT: return 41
        case .DS: return 43
        case .SSHFP: return 44
        case .RRSIG: return 46
        case .NSEC: return 47
        case .DNSKEY: return 48
        case .NSEC3: return 50
        case .SVCB: return 64
        case .HTTPS: return 65
        case .IXFR: return 251
        case .AXFR: return 252
        case .ANY: return 255
        case .unknown(let value): return value
        }
    }
    
    /// Initializer from string
    /// - Parameter description: The short string that represents the Record Type
    ///
    /// Unknown records are represented as TYPE + unsigned integer such as TYPE123
    public init?(_ description: String) {
        let uppercasedDescription = description.uppercased()
        switch uppercasedDescription {
        case "A": self = .A
        case "NS": self = .NS
        case "CNAME": self = .CNAME
        case "SOA": self = .SOA
        case "PTR": self = .PTR
        case "MX": self = .MX
        case "TXT": self = .TXT
        case "AAAA": self = .AAAA
        case "SRV": self = .SRV
        case "DNAME": self = .DNAME
        case "OPT": self = .OPT
        case "DS": self = .DS
        case "SSHFP": self = .SSHFP
        case "RRSIG": self = .RRSIG
        case "NSEC": self = .NSEC
        case "DNSKEY": self = .DNSKEY
        case "NSEC3": self = .NSEC3
        case "SVCB": self = .SVCB
        case "HTTPS": self = .HTTPS
        case "IXFR": self = .IXFR
        case "AXFR": self = .AXFR
        case "ANY": self = .ANY
        default:
            // Limit to 5 digits since a UInt16 is limited to 65535
            let pattern = #"^TYPE(\d{1,5})$"#
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }
            
            if let result = regex.firstMatch(in: uppercasedDescription, options: [], range: NSRange(uppercasedDescription.startIndex..., in: uppercasedDescription)) {
                if let range = Range(result.range(at: 1), in: uppercasedDescription) {
                    if let value = UInt16(uppercasedDescription[range]) {
                        self.init(value)
                        return
                    }
                }
            }
            return nil
        }
    }
    
    /// A short user-friendly string that describes the Record Type
    ///
    /// Unknown records are represented as TYPE + unsigned integer such as TYPE123
    public var description: String {
        switch self {
        case .A: return "A"
        case .NS: return "NS"
        case .CNAME: return "CNAME"
        case .SOA: return "SOA"
        case .PTR: return "PTR"
        case .MX: return "MX"
        case .TXT: return "TXT"
        case .AAAA: return "AAAA"
        case .SRV: return "SRV"
        case .DNAME: return "DNAME"
        case .OPT: return "OPT"
        case .DS: return "DS"
        case .SSHFP: return "SSHFP"
        case .RRSIG: return "RRSIG"
        case .NSEC: return "NSEC"
        case .DNSKEY: return "DNSKEY"
        case .NSEC3: return "NSEC3"
        case .SVCB: return "SVCB"
        case .HTTPS: return "HTTPS"
        case .IXFR: return "IXFR"
        case .AXFR: return "AXFR"
        case .ANY: return "ANY"
        case .unknown(let value): return "TYPE\(value)"
        }
    }
    
    public static func == (lhs: DNSRecordType, rhs: DNSRecordType) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
