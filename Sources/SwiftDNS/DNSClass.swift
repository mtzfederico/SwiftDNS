//
//  DNSClass.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The DNS Class as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)
public enum DNSClass: Equatable, LosslessStringConvertible, Sendable, CaseIterable {
    public static let allCases: [DNSClass] = [.internet, .chaos, .hesiod, .none, .any]
    
    case internet // = 1
    case chaos // = 3
    case hesiod // = 4
    case none // = 254
    case any // = 255
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 1:
            self = .internet
        case 3:
            self = .chaos
        case 4:
            self = .hesiod
        case 254:
            self = .none
        case 255:
            self = .any
        default:
            self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .internet:
            return 1
        case .chaos:
            return 3
        case .hesiod:
            return 4
        case .none:
            return 254
        case .any:
            return 255
        case .unknown(let value):
            return value
        }
    }
    
    /// A short string that represents the class
    ///
    /// Unknown records are represented as CLASS + unsigned integer such as CLASS123
    public var description: String {
        switch self {
        case .internet:
            return "IN"
        case .chaos:
            return "CH"
        case .hesiod:
            return "HS"
        case .none:
            return "NONE"
        case .any:
            return "ANY"
        case .unknown(let value):
            return "CLASS\(value)"
        }
    }
    
    /// Initializer from string
    /// - Parameter description: The short string that represents the Class
    ///
    /// Unknown Classes are represented as CLASS + unsigned integer such as CLASS123
    public init?(_ description: String) {
        let uppercasedDescription = description.uppercased()
        switch uppercasedDescription {
        case "IN": self = .internet
        case "CH": self = .chaos
        case "HS": self = .hesiod
        case "NONE": self = .none
        case "ANY": self = .any
        default:
            // Limit to 5 digits since a UInt16 is limited to 65535
            let pattern = #"^CLASS(\d{1,5})$"#
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
    
    public static func ==(lhs: DNSClass, rhs: DNSClass) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
