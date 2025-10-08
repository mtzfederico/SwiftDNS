//
//  EDNSOptionCode.swift
//  SwiftDNS
//
//  Created by FedeMtz on 2025-10-04
// 

import Foundation

/// The EDNS Options Codes
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
public enum EDNSOptionCode: UInt16, Sendable {
    case reserved = 0
    case LLQ = 1
    case updateLease = 2
    case NSID = 3
    case DAU = 5
    case DHU = 6
    case N3U = 7
    case ClientSubnet = 8
    case EDNSExpire = 9
    case COOKIE = 10
    case KeepAlive = 11
    case Padding = 12
    // https://www.rfc-editor.org/rfc/rfc8914.html
    case ExtendedDNSError = 15
    case unknown
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let type = try container.decode(UInt16.self)
        
        self.init(rawValue: type)!
    }
    
    /// A short user-friendly string that describes the EDNS Option Code
    public var description: String {
        switch self {
        case .reserved: return "RESERVED"
        case .LLQ: return "LLQ"
        case .updateLease: <#code#>
        case .NSID: return "NSID"
        case .DAU: return "DAU"
        case .DHU: return "DHU"
        case .N3U: return "N3U"
        case .ClientSubnet: return "Client Subnet"
        case .EDNSExpire: <#code#>
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
