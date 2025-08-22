//
//  ResourceRecord.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The data format used for the answer, authority, and additional sections of a DNS packet.
/// To initialize from data use DNSCoder's decodeResourceRecord(data:offset:)
public struct ResourceRecord: Sendable {
    /*
     The answer, authority, and additional sections share the same format.
     There is a variable number of resource records, the number of
     records is specified in the corresponding count fields in the header.
     Resource record format:
                                         1  1  1  1  1  1
           0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                                               |
         /                                               /
         /                      NAME                     /
         |                                               |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                      TYPE                     |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                     CLASS                     |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                      TTL                      |
         |                                               |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                   RDLENGTH                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
         /                     RDATA                     /
         /                                               /
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */
    
    /// a domain name to which this resource record pertains
    public let name: String
    /// An unsigned integer that specifies the time interval (in seconds) that the resource record may be cached before it should be discarded.  Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    public let ttl: UInt32
    public let Class: DNSClass
    public let type: DNSRecordType
    public let value: String
    
    public init(name: String, ttl: UInt32, Class: DNSClass, type: DNSRecordType, value: String) {
        self.name = name
        self.ttl = ttl
        self.Class = Class
        self.type = type
        self.value = value
    }
    
    /// Returns the decoded response
    public init(data: Data, offset: inout Int) throws {
        let (domainName, domainLength) = DNSCoder.parseDomainName(data: data, offset: offset)
        // print("[decodeResourceRecord] domain name: \(domainName), length: \(domainLength). at offset: \(offset)")
        offset += domainLength
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 10 <= data.count else {
            // print("[decodeResourceRecord] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.invalidData
        }
        
        guard let type = DNSRecordType(rawValue: UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })) else {
            // print("[decodeResourceRecord] Failed to parse TYPE. offset: \(offset)")
            throw DNSError.parsingError(DNSError.invalidData)
        }
        
        offset += 2 // type
        
        guard let Class = DNSClass(rawValue: UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })) else {
            // print("[decodeResourceRecord] Failed to parse CLASS. offset: \(offset)")
            throw DNSError.invalidData
        }
        
        offset += 2 // class
        let ttl = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        offset += 4 // ttl
        let rdlength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        // print("[decodeResourceRecord] rdlength: \(rdlength). at offset: \(offset)")
        offset += 2 // rdLength
        
        switch type {
        case .A:
            guard rdlength == 4 && offset + 4 <= data.count else {
                // print("failed to parse A record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }
            
            let ipBytes = data.subdata(in: offset..<offset+4)
            let ip = ipBytes.map { String($0) }.joined(separator: ".")
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: ip)
            return
        case .AAAA:
            guard rdlength == 16 && offset + 16 <= data.count else {
                // print("failed to parse AAAA record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }
            
            let ipBytes = data.subdata(in: offset..<offset+16)
            
            // Convert every 2 bytes into one 16-bit block
            var segments: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                let part = (UInt16(ipBytes[i]) << 8) | UInt16(ipBytes[i + 1])
                segments.append(String(format: "%x", part))
            }
            
            let ip = segments.joined(separator: ":")
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: ip)
            return
        case .MX:
            guard rdlength >= 3 && offset + Int(rdlength) <= data.count else {
                // print("failed to parse MX record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }

            let preference = data.subdata(in: offset..<offset+2).withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }

            let (domain, _) = DNSCoder.parseDomainName(data: data, offset: offset + 2)
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: "\(preference) \(domain)")
            return
        case .CNAME, .NS, .PTR:
            guard rdlength >= 3 && offset + Int(rdlength) <= data.count else {
                // print("failed to parse CNAME record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }
            let (domain, _) = DNSCoder.parseDomainName(data: data, offset: offset)
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: domain)
            return
        case .TXT:
            guard offset + Int(rdlength) <= data.count else {
                // print("Failed to parse TXT record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }

            let txtData = data.subdata(in: offset..<offset+Int(rdlength))
            var position = 0
            var strings: [String] = []

            while position < txtData.count {
                let length = Int(txtData[position])
                position += 1

                guard position + length <= txtData.count else {
                    offset += Int(rdlength)
                    throw DNSError.parsingError(DNSError.invalidData)
                }

                let stringData = txtData[position..<position+length]
                if let str = String(data: stringData, encoding: .utf8) {
                    strings.append(str)
                } else {
                    strings.append(stringData.map { String(format: "\\x%02x", $0) }.joined())
                }

                position += length
            }

            let value = strings.joined(separator: " ")
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .SOA:
            guard offset + Int(rdlength) <= data.count else {
                // print("Failed to parse SOA record: offset out of bounds")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }

            let start = offset

            // Parse MNAME
            let (mname, mnameLen) = DNSCoder.parseDomainName(data: data, offset: offset)
            offset += mnameLen

            // Parse RNAME
            let (rname, rnameLen) = DNSCoder.parseDomainName(data: data, offset: offset)
            offset += rnameLen

            // Check remaining size
            let remaining = start + Int(rdlength) - offset
            guard remaining >= 20 else {
                // print("SOA RDATA too short after domain names")
                offset = start + Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }

            // Parse the 5 UInt32 values
            let serial = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            let refresh = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            let retry = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            let expire = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            let minimum = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4

            let value = "\(mname) \(rname) \(serial) \(refresh) \(retry) \(expire) \(minimum)"

            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        default:
            guard offset + Int(rdlength) <= data.count else {
                // print("default: failed to read RDATA, skipping. Type: \(type.rawValue), class: \(Class), length: \(rdlength), ttl: \(ttl)")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData)
            }
            
            let rdata = data.subdata(in: offset..<offset+Int(rdlength))
            offset += Int(rdlength)
            
            // decode as string, fallback to hex
            let value: String
            if let str = String(data: rdata, encoding: .utf8), str.isPrintable {
                value = str
            } else {
                value = rdata.map { String(format: "%02x", $0) }.joined(separator: " ")
            }
            
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
        }
    }
    
    public static func ==(lhs: ResourceRecord, rhs: ResourceRecord) -> Bool {
        return lhs.name == rhs.name && lhs.ttl == rhs.ttl && lhs.Class == rhs.Class && lhs.type == rhs.type && lhs.value == rhs.value
    }
}
