//
//  ResourceRecord.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The data format used for the answer, authority, and additional sections of a DNS packet.
public struct ResourceRecord: Sendable, Equatable {
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
    /// The DNS Class of the record
    public let Class: DNSClass
    /// The DNS type of the record
    public let type: DNSRecordType
    /// The value of the DNS record
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
        let (domainName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
        // print("[decodeResourceRecord] domain name: \(domainName), length: \(domainLength). at offset: \(offset)")
        offset += domainLength
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 10 <= data.count else {
            throw DNSError.invalidData("Offset (\(offset)) over bounds (\(data.count)) for TYPE, CLASS, TTL, and RDLENGTH")
        }
        
        let rawType = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        guard let type = DNSRecordType(rawValue: rawType) else {
            // print("[decodeResourceRecord] Failed to parse TYPE. offset: \(offset)")
            throw DNSError.parsingError(DNSError.invalidData("Failed to parse TYPE: '\(rawType)'"))
        }
        
        if type == .OPT {
            throw DNSError.invalidData("OPT_RECORD")
        }
        
        offset += 2 // type
        
        let rawClass = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2 // class
        let ttl = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        offset += 4 // ttl
        /// The length in octets of the RDATA field
        let rdlength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        // print("[decodeResourceRecord] rdlength: \(rdlength). at offset: \(offset)")
        offset += 2 // rdLength
        
        guard let Class = DNSClass(rawValue: rawClass) else {
            // print("[decodeResourceRecord] Failed to parse CLASS. offset: \(offset)")
            throw DNSError.invalidData("Failed to parse CLASS: '\(rawClass)'")
        }
        
        guard rdlength <= data.count - offset else {
            throw DNSError.invalidData("RDLength is smaller than the data length. RDLength: \(rdlength), Data Length: \(data.count-offset)")
        }
        
        switch type {
        case .A:
            guard rdlength == 4 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("invalid rdlength for A record: '\(rdlength)'"))
            }
            
            guard offset + 4 <= data.count else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }
            
            let ipBytes = data.subdata(in: offset..<offset+4)
            let ip = ipBytes.map { String($0) }.joined(separator: ".")
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: ip)
            return
        case .AAAA:
            guard rdlength == 16 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("invalid rdlength for AAAA record: '\(rdlength)'"))
            }
            
            guard offset + 16 <= data.count else {
                // print("failed to parse AAAA record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
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
            guard rdlength >= 3 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength too small for MX record: '\(rdlength)'"))
            }
            
            guard offset + Int(rdlength) <= data.count else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }

            let preference = data.subdata(in: offset..<offset+2).withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }

            let (domain, _) = try DNSClient.parseDomainName(data: data, offset: offset + 2)
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: "\(preference) \(domain)")
            return
        case .CNAME, .NS, .PTR:
            guard rdlength >= 2 else { // was 3, but it breaks CNAMES pointing to the root. www.example.net --> example.net
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength too small for \(type.description) record: '\(rdlength)'"))
            }
            
            guard offset + Int(rdlength) <= data.count else {
                // print("failed to parse CNAME record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }
            let (domain, _) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += Int(rdlength)
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: domain)
            return
        case .TXT:
            guard offset + Int(rdlength) <= data.count else {
                // print("Failed to parse TXT record")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("txt rdlength out of bounds. '\(rdlength)'"))
            }

            let txtData = data.subdata(in: offset..<offset+Int(rdlength))
            var position = 0
            var strings: [String] = []

            while position < txtData.count {
                let length = Int(txtData[position])
                position += 1

                guard position + length <= txtData.count else {
                    offset += Int(rdlength)
                    throw DNSError.parsingError(DNSError.invalidData("length of position in txt record out of bounds"))
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
        case .SRV:
            guard rdlength >= 7 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength too small for SRV record: '\(rdlength)'"))
            }
            
            guard offset + Int(rdlength) <= data.count else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }

            let priority = try data.readUInt16(at: offset)
            offset += 2
            
            let weight = try data.readUInt16(at: offset)
            offset += 2
            
            let port = try data.readUInt16(at: offset)
            offset += 2

            let (target, targetLen) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += targetLen

            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: "\(priority) \(weight) \(port) \(target)")
            return
            
        case .SOA:
            /*
            guard rdlength >= 4 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength too small for soa record: '\(rdlength)'"))
            }*/
            
            guard offset + Int(rdlength) <= data.count else {
                // print("Failed to parse SOA record: offset out of bounds")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }

            let start = offset
            
            // Parse MNAME
            let (mname, mnameLen) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += mnameLen

            // Parse RNAME
            let (rname, rnameLen) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += rnameLen

            // Check remaining size
            let remaining = start + Int(rdlength) - offset
            guard remaining >= 20 else {
                // print("SOA RDATA too short after domain names")
                offset = start + Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("soa rdata too short after domain names: \(remaining) bytes left"))
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
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
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
    
    /// Returns the data of the ResourceRecord
    internal func toData(messageLength: Int, nameOffsets: inout [String: Int]) throws -> Data {
        var bytes: Data = try DNSMessage.encodeDomainName(name: self.name, messageLength: messageLength, nameOffsets: &nameOffsets)
        
        guard type != .OPT else {
            throw DNSError.invalidData("Use EDNSMessage for OPT records")
        }
        var qtype: UInt16 = type.rawValue.bigEndian
        bytes.append(Data(bytes: &qtype, count: 2))
        
        var qclass: UInt16 = Class.rawValue.bigEndian
        bytes.append(Data(bytes: &qclass, count: 2))
        
        var ttl: UInt32 = ttl.bigEndian
        bytes.append(Data(bytes: &ttl, count: 4))
        
        /// It is the position where the data ends. The current position of the "writer".
        /// It is used to know where to point to when compressing
        var offset = messageLength + bytes.count
        
        // Increase the offset by the length of the RDLength
        offset += 2
        
        var rdata: Data = Data()
        
        switch self.type {
        case .A:
            let octets = self.value.split(separator: ".").compactMap { UInt8($0) }
            guard octets.count == 4 else {
                throw DNSError.parsingError(DNSError.invalidData("Invalid A record IP: \(value)"))
            }
            rdata.append(contentsOf: octets)
        case .AAAA:
            var dst = in6_addr()
            let success = self.value.withCString { cstr in
                inet_pton(AF_INET6, cstr, &dst)
            }
            
            guard success == 1 else {
                throw DNSError.parsingError(DNSError.invalidData("Invalid IPv6 address: '\(self.value)'"))
            }
            
            // Convert in6_addr to Data (16 bytes)
            rdata.append(Data(bytes: &dst, count: MemoryLayout<in6_addr>.size))
        case .CNAME, .NS, .PTR:
            // rdlength offset +2 was here
            let domain = try DNSMessage.encodeDomainName(name: self.value, messageLength: offset, nameOffsets: &nameOffsets)
            print("[RR toData] CNAME/NS/PTR encodedDomain: \(domain.hexEncodedString()) | length: \(domain.count)")
            offset += domain.count
            rdata.append(domain)
        case .MX:
            let parts = self.value.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let preference = UInt16(parts[0]) else {
                throw DNSError.parsingError(DNSError.invalidData("Invalid MX record value: \(value)"))
            }
            
            var pref: UInt16 = preference.bigEndian
            rdata.append(Data(bytes: &pref, count: 2))
            offset += 2 // rdata.count
            #warning("look at cname above")
            rdata.append(try DNSMessage.encodeDomainName(name: String(parts[1]), messageLength: offset, nameOffsets: &nameOffsets))
        case .TXT:
            let txtBytes = Array(self.value.utf8)
            guard txtBytes.count <= 255 else {
                throw DNSError.parsingError(DNSError.invalidData("TXT record too long"))
            }
            rdata.append(UInt8(txtBytes.count))
            rdata.append(contentsOf: txtBytes)
        case .SRV:
            let values = value.split(separator: " ")
            guard values.count == 4 else {
                throw DNSError.invalidData("SRV record value must contain 4 values separated by space")
            }

            // priority
            rdata.append(contentsOf: withUnsafeBytes(of: UInt16(values[0])!.bigEndian) { Data($0) })
            
            // weight
            rdata.append(contentsOf: withUnsafeBytes(of: UInt16(values[1])!.bigEndian) { Data($0) })
            
            // port
            rdata.append(contentsOf: withUnsafeBytes(of: UInt16(values[2])!.bigEndian) { Data($0) })
            
            // target
            offset += rdata.count
            rdata.append(try DNSMessage.encodeDomainName(name: String(values[3]), messageLength: offset, nameOffsets: &nameOffsets))
            // rdata.append(try QuestionSection.encodeDomainName(name: String(values[3])))
        case .SOA:
            let values = value.split(separator: " ")
            guard values.count == 7 else {
                throw DNSError.invalidData("SOA record value must contain 7 values separated by space")
            }
            
            guard let serial = UInt32(values[2]), let refresh = UInt32(values[3]), let retry = UInt32(values[4]), let expire = UInt32(values[5]), let minimum = UInt32(values[6]) else {
                throw DNSError.invalidData("SOA record values must be convertible to UInt32")
            }
            
            print("nameOffsets before mname: \(nameOffsets)")
            
            let MNAME = String(values[0])
            let encodedMNAME = try DNSMessage.encodeDomainName(name: MNAME, messageLength: offset, nameOffsets: &nameOffsets)
            print("nameOffsets after mname: \(nameOffsets)")
            offset += encodedMNAME.count
            rdata.append(encodedMNAME)
            
            let RNAME = String(values[1])
            let encodedRNAME = try DNSMessage.encodeDomainName(name: RNAME, messageLength: offset, nameOffsets: &nameOffsets)
            print("nameOffsets after rname: \(nameOffsets)")
            offset += encodedRNAME.count
            rdata.append(encodedRNAME)
            
            rdata.append(contentsOf: withUnsafeBytes(of: serial.bigEndian) { Data($0) })
            
            rdata.append(contentsOf: withUnsafeBytes(of: refresh.bigEndian) { Data($0) })
            
            rdata.append(contentsOf: withUnsafeBytes(of: retry.bigEndian) { Data($0) })
            
            rdata.append(contentsOf: withUnsafeBytes(of: expire.bigEndian) { Data($0) })
            
            rdata.append(contentsOf: withUnsafeBytes(of: minimum.bigEndian) { Data($0) })
        default:
            // raw UTF-8 string
            guard let fallback = self.value.data(using: .utf8) else {
                throw DNSError.parsingError(DNSError.invalidData("Could not encode RDATA for \(type)"))
            }
            rdata.append(fallback)
        }
        
        let rdlength: UInt16 = UInt16(rdata.count).bigEndian
        // bytes.append(Data(bytes: &rdlength, count: 2))
        bytes.append(contentsOf: withUnsafeBytes(of: rdlength) { Data($0) })
        bytes.append(rdata)
        
        return bytes
    }
    
    /// Returns a string with the Name, TTL, Class, Type, and Value
    public var description: String {
        return "\(name) \(ttl) \(Class.displayName) \(type) \(value)"
    }
    
    public static func ==(lhs: ResourceRecord, rhs: ResourceRecord) -> Bool {
        return lhs.name == rhs.name && lhs.ttl == rhs.ttl && lhs.Class == rhs.Class && lhs.type == rhs.type && lhs.value == rhs.value
    }
}
