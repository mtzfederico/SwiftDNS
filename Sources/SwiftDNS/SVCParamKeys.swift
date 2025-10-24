//
//  SVCParamKeys.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-16
// 

import Foundation

/// The Service Parameter Keys used in SVCB and HTTPS Resource Records
///
/// Defined by [IANA](https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml)
enum SVCParamKeys: Equatable, LosslessStringConvertible, Sendable, CaseIterable, Hashable {
    static let allCases: [SVCParamKeys] = [.mandatory, .alpn, .noDefaultAlpn, .port, .ipv4hint, .ech, .ipv6hint, .dohpath, .ohttp, .tlsSupportedGroups, .docpath]
    /// Mandatory keys in this RR
    case mandatory
    /// Additional supported protocols
    case alpn
    /// No support for default protocol
    case noDefaultAlpn
    /// Port for alternative endpoint
    case port
    /// IPv4 address hints
    case ipv4hint
    /// TLS Encrypted ClientHello Config
    case ech
    /// IPv6 address hints
    case ipv6hint
    /// DNS over HTTPS path template
    case dohpath
    /// Denotes that a service operates an Oblivious HTTP target
    case ohttp
    /// Supported groups in TLS
    case tlsSupportedGroups
    ///  DNS over CoAP resource path
    case docpath
    /// Keys 65280-65534 are reserved for private use
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 0:
            self = .mandatory
        case 1:
            self = .alpn
        case 2:
            self = .noDefaultAlpn
        case 3:
            self = .port
        case 4:
            self = .ipv4hint
        case 5:
            self = .ech
        case 6:
            self = .ipv6hint
        case 7:
            self = .dohpath
        case 8:
            self = .ohttp
        case 9:
            self = .tlsSupportedGroups
        case 10:
            self = .docpath
        default:
            self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .mandatory:
            return 0
        case .alpn:
            return 1
        case .noDefaultAlpn:
            return 2
        case .port:
            return 3
        case .ipv4hint:
            return 4
        case .ech:
            return 5
        case .ipv6hint:
            return 6
        case .dohpath:
            return 7
        case .ohttp:
            return 8
        case .tlsSupportedGroups:
            return 9
        case .docpath:
            return 10
        case .unknown(let value):
            return value
        }
    }
    
    init?(_ description: String) {
        let lowercasedDescription = description.lowercased()
        switch lowercasedDescription {
        case "mandatory":
            self = .mandatory
        case "alpn":
            self = .alpn
        case "no-default-alpn":
            self = .noDefaultAlpn
        case "port":
            self = .port
        case "ipv4hint":
            self = .ipv4hint
        case "ech":
            self = .ech
        case "ipv6hint":
            self = .ipv6hint
        case "dohpath":
            self = .dohpath
        case "ohttp":
            self = .ohttp
        case "tlssupportedgroups":
            self = .tlsSupportedGroups
        case "docpath":
            self = .docpath
        default:
            // Limit to 5 digits since a UInt16 is limited to 65535
            let pattern = #"^key(\d{1,5})$"#
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else { return nil }
            
            if let result = regex.firstMatch(in: lowercasedDescription, options: [], range: NSRange(lowercasedDescription.startIndex..., in: lowercasedDescription)) {
                if let range = Range(result.range(at: 1), in: lowercasedDescription) {
                    if let value = UInt16(lowercasedDescription[range]) {
                        self.init(value)
                        return
                    }
                }
            }
            return nil
        }
    }
    
    var description: String {
        switch self {
        case .mandatory:
            return "mandatory"
        case .alpn:
            return "alpn"
        case .noDefaultAlpn:
            return "no-default-alpn"
        case .port:
            return "port"
        case .ipv4hint:
            return "ipv4hint"
        case .ech:
            return "ech"
        case .ipv6hint:
            return "ipv6hint"
        case .dohpath:
            return "dohpath"
        case .ohttp:
            return "ohttp"
        case .tlsSupportedGroups:
            return "tlssupportedgroups"
        case .docpath:
            return "docpath"
        case .unknown(let value):
            return "key\(value)"
        }
    }
    
    
}
