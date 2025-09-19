//
//  DNSRecordType.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// DNS record type
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4)
public enum DNSRecordType: UInt16, Decodable, Equatable, CustomStringConvertible, Sendable {
    case A = 1
    case NS = 2
    case CNAME = 5
    case SOA = 6
    case PTR = 12
    case MX = 15
    case TXT = 16
    case AAAA = 28
    case SRV = 33
    case DNAME = 39
    case OPT = 41
    case DS = 43
    case SSHFP = 44
    case RRSIG = 46
    case NSEC = 47
    case DNSKEY = 48
    case HTTPS = 65
    case AXFR = 252
    case ANY = 255
    case unknown
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let type = try container.decode(UInt16.self)
        
        self.init(rawValue: type)!
    }
    
    /// /// A short user-friendly string that describes the Record Type
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
        case .HTTPS: return "HTTPS"
        case .AXFR: return "AXFR"
        case .ANY: return "ANY"
        case .unknown: return "Unkown: '\(self.rawValue)'"
        }
    }
    
    public static func == (lhs: DNSRecordType, rhs: DNSRecordType) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
