//
//  DNSClass.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The DNS Class as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)
public enum DNSClass: UInt16, Equatable, CustomStringConvertible, Sendable, CaseIterable {
    case internet = 1
    case chaos = 3
    case hesiod = 4
    case none = 254
    case any = 255
    case unknown
    
    /// A short string that represents the class
    public var description: String {
        switch self {
        case .internet:
            return "IN"
        case .chaos:
            return "CH"
        case .hesiod:
            return "HS"
        case .none:
            return "none"
        case .any:
            return "any"
        case .unknown:
            return "Unkown: \(self.rawValue)"
        }
    }
    
    public static func ==(lhs: DNSClass, rhs: DNSClass) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
