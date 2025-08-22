//
//  DNSClass.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

public enum DNSClass: UInt16, Decodable, Equatable, Sendable {
    case internet = 1
    case chaos = 3
    case hesiod = 4
    case none = 254
    case any = 255
    case unknown
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let type = try container.decode(UInt16.self)
        
        self.init(rawValue: type)!
    }
    
    public var displayName: String {
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
        return lhs.displayName == rhs.displayName
    }
}
