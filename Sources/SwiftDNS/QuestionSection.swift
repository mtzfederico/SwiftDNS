//
//  QuestionSection.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

public struct QuestionSection {
    /// a domain name represented as a sequence of labels, where each label consists of a length octet followed by that number of octets.  The domain name terminates with the zero length octet for the null label of the root.  Note that this field may be an odd number of octets; no padding is used.
    var QNAME: String
    /// a two octet code which specifies the type of the query. The values for this field include all codes valid for a TYPE field, together with some more general codes which can match more than one type of RR.
    var QTYPE: DNSRecordType
    /// two octets which specify the class of the data in the RDATA field.
    /// a two octet code that specifies the class of the query. For example, the QCLASS field is IN for the Internet.
    var QCLASS: DNSClass
    
    public init(host: String, type: DNSRecordType, CLASS: DNSClass = .internet) {
        self.QNAME = host
        self.QTYPE = type
        self.QCLASS = CLASS
    }
    
    public init(data: Data, offset: inout Int) throws {
        let (domainName, domainLength) = DNSCoder.parseDomainName(data: data, offset: offset)
        // print("[decodeQuestion] domain name: \(domainName), length: \(domainLength)")
        offset += domainLength
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 4 <= data.count else { // was + 10
            // print("[decodeQuestion] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.outOfBounds
        }
        
        guard let type = DNSRecordType(rawValue: try data.readUInt16(at: offset)) else {
            // print("[decodeQuestion] Failed to parse TYPE. offset: \(offset), data.count: \(data.count)")
            throw DNSError.parsingError(DNSError.invalidData)
        }
        
        offset += 2 // type
        
        guard let Class = DNSClass(rawValue: try data.readUInt16(at: offset)) else {
            // print("[decodeQuestion] Failed to parse CLASS. offset: \(offset), data.count: \(data.count)")
            throw DNSError.parsingError(DNSError.invalidData)
        }
        
        offset += 2 // class
        
        self.QNAME = domainName
        self.QTYPE = type
        self.QCLASS = Class
    }
    
    public func toData() -> Data {
        var bytes = Data()
        
        let labels = QNAME.split(separator: ".")
        for label in labels {
            let length = UInt8(label.count)
            bytes.append(length)
            bytes.append(contentsOf: label.utf8)
        }
        
        bytes.append(0) // End of domain name
        
        var qtype: UInt16 = QTYPE.rawValue.bigEndian
        var qclass: UInt16 = QCLASS.rawValue.bigEndian
        bytes.append(Data(bytes: &qtype, count: 2))
        bytes.append(Data(bytes: &qclass, count: 2))
        
        return bytes
    }
    
    static func == (lhs: QuestionSection, rhs: QuestionSection) -> Bool {
        return lhs.QNAME == rhs.QNAME && lhs.QTYPE == rhs.QTYPE && lhs.QCLASS == rhs.QCLASS
    }
}
