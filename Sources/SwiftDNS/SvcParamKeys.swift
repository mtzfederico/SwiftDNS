//
//  SvcParamKeys.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-16
// 

import Foundation

enum SVCParamKeys: Equatable, LosslessStringConvertible, Sendable, CaseIterable, Hashable {
    static let allCases: [SVCParamKeys] = [.mandatory, .alpn, .noDefaultAlpn, .port, .ipv4hint, .ech, .ipv6hint]
    
    case mandatory
    case alpn
    case noDefaultAlpn
    case port
    case ipv4hint
    case ech
    case ipv6hint
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
        case .unknown(let value):
            return "key\(value)"
        }
    }
    
    
}
