//
//  EDNSOptionCode.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-04
// 

import Foundation

/// The EDNS Options Codes
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
public enum EDNSOptionCode: UInt16, Sendable, CustomStringConvertible {
    case reserved = 0
    case LLQ = 1
    case updateLease = 2
    case NSID = 3
    case DAU = 5
    case DHU = 6
    case N3U = 7
    /// The EDNS Client Subnet option as defined in [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871)
    case ClientSubnet = 8
    /// The EDNS Expire option as defined in [RFC 7314](https://www.rfc-editor.org/rfc/rfc7314.html)
    case EDNSExpire = 9
    /// The EDNS Cookie option as defined in [RFC 7873](https://datatracker.ietf.org/doc/html/rfc7873)
    case COOKIE = 10
    case KeepAlive = 11
    case Padding = 12
    /// The EDNS Extended DNS Error option as defined in [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914)
    case ExtendedDNSError = 15
    case unknown
    
    /// A short user-friendly string that describes the EDNS Option Code. It is not always the name and it may contain spaces
    public var description: String {
        switch self {
        case .reserved: return "RESERVED"
        case .LLQ: return "LLQ"
        case .updateLease: return "Update Lease"
        case .NSID: return "NSID"
        case .DAU: return "DAU"
        case .DHU: return "DHU"
        case .N3U: return "N3U"
        case .ClientSubnet: return "Client Subnet"
        case .EDNSExpire: return "EDNS Expire"
        case .COOKIE: return "Cookie"
        case .KeepAlive: return "KeepAlive"
        case .Padding: return "Padding"
        case .ExtendedDNSError: return "Extended DNS Error"
        case .unknown: return "Unkown: '\(self.rawValue)'"
        }
    }
    
    public static func == (lhs: EDNSOptionCode, rhs: EDNSOptionCode) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
