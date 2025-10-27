//
//  EDNSOptionCode.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-04
// 

import Foundation

/// The EDNS Options Codes
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
public enum EDNSOptionCode: Sendable, LosslessStringConvertible, CaseIterable {
    public static let allCases: [EDNSOptionCode] = [.reserved, .LLQ, .updateLease, .NSID, .DAU, .DHU, .N3U, .ClientSubnet, .EDNSExpire, .COOKIE, .KeepAlive, .Padding, .ExtendedDNSError]
    
    case reserved // = 0
    case LLQ // = 1
    case updateLease // = 2
    /// The DNS Name Server Identifier option as defined in [RFC 5001](https://datatracker.ietf.org/doc/html/rfc5001)
    case NSID // = 3
    case DAU // = 5
    case DHU // = 6
    case N3U // = 7
    /// The EDNS Client Subnet option as defined in [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871)
    case ClientSubnet // = 8
    /// The EDNS Expire option as defined in [RFC 7314](https://www.rfc-editor.org/rfc/rfc7314.html)
    case EDNSExpire // = 9
    /// The EDNS Cookie option as defined in [RFC 7873](https://datatracker.ietf.org/doc/html/rfc7873)
    case COOKIE // = 10
    case KeepAlive // = 11
    case Padding // = 12
    /// The EDNS Extended DNS Error option as defined in [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914)
    case ExtendedDNSError // = 15
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 0:
            self = .reserved
        case 1:
            self = .LLQ
        case 2:
            self = .updateLease
        case 3:
            self = .NSID
        case 5:
            self = .DAU
        case 6:
            self = .DHU
        case 7:
            self = .N3U
        case 8:
            self = .ClientSubnet
        case 9:
            self = .EDNSExpire
        case 10:
            self = .COOKIE
        case 11:
            self = .KeepAlive
        case 12:
            self = .Padding
        case 15:
            self = .ExtendedDNSError
        default:
            self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .reserved:
            return 0
        case .LLQ:
            return 1
        case .updateLease:
            return 2
        case .NSID:
            return 3
        case .DAU:
            return 5
        case .DHU:
            return 6
        case .N3U:
            return 7
        case .ClientSubnet:
            return 8
        case .EDNSExpire:
            return 9
        case .COOKIE:
            return 10
        case .KeepAlive:
            return 11
        case .Padding:
            return 12
        case .ExtendedDNSError:
            return 15
        case .unknown(let value):
            return value
        }
    }
    
    public init?(_ description: String) {
        switch description {
        case "RESERVED":
            self = .reserved
        case "LLQ":
            self = .LLQ
        case "UpdateLease":
            self = .updateLease
        case "NSID":
            self = .NSID
        case "DAU":
            self = .DAU
        case "DHU":
            self = .DHU
        case "N3U":
            self = .N3U
        case "ClientSubnet":
            self = .ClientSubnet
        case "EDNSExpire":
            self = .EDNSExpire
        case "COOKIE":
            self = .COOKIE
        case "KeepAlive":
            self = .KeepAlive
        case "Padding":
            self = .Padding
        case "ExtendedDNSError":
            self = .ExtendedDNSError
        default:
            // Limit to 5 digits since a UInt16 is limited to 65535
            let pattern = #"^OPTION(\d{1,5})$"#
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
    
    /// A short user-friendly string that describes the EDNS Option Code. It is not always the name and it may contain spaces
    public var description: String {
        switch self {
        case .reserved: return "RESERVED"
        case .LLQ: return "LLQ"
        case .updateLease: return "UpdateLease"
        case .NSID: return "NSID"
        case .DAU: return "DAU"
        case .DHU: return "DHU"
        case .N3U: return "N3U"
        case .ClientSubnet: return "ClientSubnet"
        case .EDNSExpire: return "EDNSExpire"
        case .COOKIE: return "COOKIE"
        case .KeepAlive: return "KeepAlive"
        case .Padding: return "Padding"
        case .ExtendedDNSError: return "ExtendedDNSError"
        case .unknown(let value): return "OPTION\(value)"
        }
    }
    
    public static func == (lhs: EDNSOptionCode, rhs: EDNSOptionCode) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
