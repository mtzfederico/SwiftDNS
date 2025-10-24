//
//  QuestionSection.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The Question section of a DNS packet
public struct QuestionSection: Sendable, Equatable, LosslessStringConvertible {
    /// a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.  The domain name terminates with the zero length octet for the null label of the root.  Note that this field may be an odd number of octets; no padding is used.
    public var QNAME: String
    /// a two octet code which specifies the type of the query. The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR.
    public var QTYPE: DNSRecordType
    /// two octets which specify the class of the data in the RDATA field.
    /// a two octet code that specifies the class of the query. For example, the QCLASS field is IN for the Internet.
    public var QCLASS: DNSClass
    
    public init(host: String, type: DNSRecordType, CLASS: DNSClass = .internet) {
        self.QNAME = host
        self.QTYPE = type
        self.QCLASS = CLASS
    }
    
    public init(data: Data, offset: inout Int) throws {
        let (domainName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
        // print("[decodeQuestion] domain name: \(domainName), length: \(domainLength)")
        offset += domainLength
        
        // Read TYPE and CLASS
        guard offset + 4 <= data.count else {
            // print("[decodeQuestion] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.invalidData("offset out of bounds for type and class")
        }
        
        let type = DNSRecordType(try data.readUInt16(at: offset))
        
        offset += 2 // type
        
        let Class = DNSClass(try data.readUInt16(at: offset))
        
        offset += 2 // class
        
        self.QNAME = domainName
        self.QTYPE = type
        self.QCLASS = Class
    }
    
    /// Encodes a Question into data
    /// - Returns: The QuestionSection as Data
    /// - Parameter includeName: When true the name is included with the data. It should only be false when handleing compression for the name outside of this function.
    public func toData(includeName: Bool = true) throws -> Data {
        var bytes: Data = Data()
        
        if includeName {
            bytes.append(try QuestionSection.encodeDomainName(name: QNAME))
        }
        
        var qtype: UInt16 = QTYPE.rawValue.bigEndian
        var qclass: UInt16 = QCLASS.rawValue.bigEndian
        bytes.append(Data(bytes: &qtype, count: 2))
        bytes.append(Data(bytes: &qclass, count: 2))
        
        return bytes
    }
    
    /// Initializes a Question Section from a string
    /// - Parameter description: A single line with the Name, Class, and Type separated by a space
    public init?(_ description: String) {
        let values = description.split(separator: " ")
        guard values.count >= 3 else { return nil }
        
        guard let Class = DNSClass(String(values[1])), let type = DNSRecordType(String(values[2])) else {
            return nil
        }
        
        QNAME = String(values[0])
        QCLASS = Class
        QTYPE = type
    }
    
    /// Returns a string with the Name, Class, and Type separated by a space
    public var description: String {
        return "\(QNAME) \(QCLASS.description) \(QTYPE.description)"
    }
    
    public static func == (lhs: QuestionSection, rhs: QuestionSection) -> Bool {
        return lhs.QNAME == rhs.QNAME && lhs.QTYPE == rhs.QTYPE && lhs.QCLASS == rhs.QCLASS
    }
    
    /// Encodes a domain name without compression
    /// - Parameter name: The domain name to encode
    /// - Returns: The domain name encoded
    ///
    /// For compression use `DNSMessage.encodeDomainName(name:messageLength:nameOffsets:)`
    public static func encodeDomainName(name: String) throws -> Data {
        // labels          63 octets or less
        // names           255 octets or less
        //
        // 4.1.4. Message compression:
        // In compression, the first two bits are ones.  This allows a pointer to be distinguished
        // from a label, since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.  (The 10 and 01 combinations
        // are reserved for future use.)
        
        var bytes = Data()
        
        let labels = name.split(separator: ".")
        
        for label in labels {
            // Each label is represented by the number of characters (8 bits) followed by the chracters themselves (each one is 8 bits)
            let length = UInt8(label.count)
            
            if length > 63 {
                throw DNSError.invalidData("DNS label cannot have more than 63 characters. Label has \(length) characters")
            }
            
            bytes.append(length)
            bytes.append(contentsOf: label.utf8)
        }
        
        bytes.append(0) // End of domain name
        return bytes
    }
}
