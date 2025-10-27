//
//  ResourceRecord.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation
import Network

/// The data format used for the answer, authority, and additional sections of a DNS packet.
public struct ResourceRecord: Sendable, Equatable, LosslessStringConvertible {
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
    
    /// The domain name to which this resource record belongs
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
        let type = DNSRecordType(rawType)
        
        if type == .OPT {
            offset -= domainLength
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
        
        let Class = DNSClass(rawClass)
        
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
            let ip = ResourceRecord.decodeIPv4(ipBytes)
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
            let ip = ResourceRecord.decodeIPv6(ipBytes)
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
        case .NS, .CNAME, .PTR, .DNAME:
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
        case .DS:
            let keyTag = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += 2
            
            let algorithm: UInt8 = data[offset]
            offset += 1
            
            let digestType: UInt8 = data[offset]
            offset += 1
            
            guard digestType == 1 else {
                throw DNSError.invalidData("Digest Type for DS record not suported: \(digestType)")
            }
            
            // SHA-1 (digest type 1) is 20 bytes long
            // https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1.4
            let digest = data.subdata(in: offset..<offset+20).hexEncodedString()
            offset += 20
            
            let value = "\(keyTag) \(algorithm) \(digestType) \(digest)"

            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .SSHFP:
            guard rdlength >= 2 else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength too small for SSHFP record: '\(rdlength)'"))
            }
            
            guard offset + Int(rdlength) <= data.count else {
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("rdlength out of bounds"))
            }
            
            let algorithm: UInt8 = data[offset]
            offset += 1
            
            let fingerprintType: UInt8 = data[offset]
            offset += 1
            
            let range = offset..<offset+Int(rdlength-2)
            let fingerprint = data.subdata(in: range)
            offset += Int(rdlength)
            
            let value = "\(algorithm) \(fingerprintType) \(fingerprint.hexEncodedString())"
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .RRSIG:
            let typeCovered = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += 2
            
            let algorithm: UInt8 = data[offset]
            offset += 1
            
            let labels: UInt8 = data[offset]
            offset += 1
            
            let originalTTL = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            
            let signatureExpiration = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            
            let signatureInception = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
            offset += 4
            
            let keyTag = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += 2
            
            let (signerName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += domainLength
            
            // depends on the algorithm
            let signature = data.subdata(in: offset..<Int(rdlength))
            offset += signature.count
            
            let value = "\(typeCovered) \(algorithm) \(labels) \(originalTTL) \(signatureExpiration) \(signatureInception) \(keyTag) \(signerName) \(signature.base64EncodedString())"
            
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .NSEC:
            // decode the name with no compression
            let (nextDomainName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += domainLength
            
            let typeBitMapsLength = Int(rdlength) - offset
            
            guard data.count >= (offset + typeBitMapsLength) else {
                throw DNSError.invalidData("Failed to parse NSEC record: offset (\(offset + typeBitMapsLength)) out of bounds (\(data.count))")
            }
            
            var types: [String] = []
            
            let max = offset + typeBitMapsLength
            while offset < max {
                let blockNumber = data[offset]
                offset += 1
                let bitmapLength = data[offset]
                offset += 1
                let bitmap = data.subdata(in: offset..<offset+Int(bitmapLength))
                let count = bitmap.count
                offset += Int(count)
                
                for (i, byte) in bitmap.enumerated() {
                    for bit in 0..<8 {
                        if byte & (1 << (7 - bit)) != 0 {
                            let typeCode = UInt16(blockNumber) * 256 + UInt16(i * 8 + bit)
                            print("blockNumber: \(blockNumber), bitmapLength: \(bitmapLength), typeCode: \(typeCode)")
                            let type = DNSRecordType(typeCode)
                            types.append(type.description)
                        }
                    }
                }
            }
            
            let value = "\(nextDomainName) \(types.joined(separator: " "))"
            
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .DNSKEY:
            let flags = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += 2
            
            let Protocol: UInt8 = data[offset]
            offset += 1
            
            guard Protocol == 3 else {
                throw DNSError.invalidData("Protocol for DNSKEY record must be 3: \(Protocol)")
            }
            
            let algorithm: UInt8 = data[offset]
            offset += 1
            
            let publicKey = data.subdata(in: offset..<offset + Int(rdlength-4))
            offset += publicKey.count
            
            let value = "\(flags) \(Protocol) \(algorithm) \(publicKey.base64EncodedString())"
            
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
            return
        case .SVCB, .HTTPS:
            let svcPriority = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += 2
            let (targetName, len) = try DNSClient.parseDomainName(data: data, offset: offset)
            offset += len
            
            var value = "\(svcPriority) \(targetName)"
            
            if rdlength > 2 + Int(len) {
                let svcParams = data.subdata(in: offset..<(offset + Int(rdlength) - (2 + len)))
                let max = svcParams.count + offset
                
                guard max <= Int(rdlength)+offset else {
                    throw DNSError.invalidData("\(type.description) record parametrs over bounds \(max)")
                }
                
                while offset < max {
                    print("** while offset < max begins **")
                    // Defined in https://www.rfc-editor.org/rfc/rfc9460.html#iana-keys
                    let svcParamKey = SVCParamKeys(UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) }))
                    offset += 2
                    let svcParamValueLength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
                    offset += 2
                    
                    guard svcParamValueLength <= data.count else {
                        throw DNSError.invalidData("SVC Param value length out of bounds")
                    }
                    
                    let svcParamValueData = data.subdata(in: offset..<offset+Int(svcParamValueLength))
                    
                    switch svcParamKey {
                    case .mandatory:
                        // it is a list of keys that are mandatory to be supported by the client.
                        // If the client doesn't support one of them, it should ignore this RR.
                        var mandatoryKeys: [String] = []
                        var mandatoryOffset = 0
                        
                        // get the number of keys
                        // each key is a UInt16 (2 bytes)
                        for i in 0...svcParamValueLength/2 {
                            let rawKey = UInt16(bigEndian: svcParamValueData.subdata(in: mandatoryOffset..<mandatoryOffset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
                            mandatoryOffset += 2
                            
                            let key = SVCParamKeys(rawKey)
                            mandatoryKeys.append(key.description)
                        }
                        
                        value.append(" \(svcParamKey.description)=\(mandatoryKeys.joined(separator: ","))")
                    case .alpn:
                        var alpnValue: [String] = []
                        var alpnOffset = 0
                        while alpnOffset < svcParamValueData.count {
                            let len = svcParamValueData[alpnOffset]
                            alpnOffset += 1
                            let alpnData = svcParamValueData.subdata(in: alpnOffset..<Int(len)+alpnOffset)
                            alpnOffset += alpnData.count
                            if let str = String(data: alpnData, encoding: .utf8) {
                                alpnValue.append(str)
                            }
                        }
                        
                        value.append(" \(svcParamKey.description)=\(alpnValue.joined(separator: ","))")
                    case .noDefaultAlpn:
                        // there should be no data for this key, but we need the '=' for parsing it in toData (the values are split using it).
                        value.append(" \(svcParamKey.description)=\(svcParamValueLength > 0 ? "0x\(svcParamValueData.hexEncodedString())": "")")
                    case .port:
                        let port = UInt16(bigEndian: svcParamValueData.withUnsafeBytes { $0.load(as: UInt16.self) })
                        value.append(" \(svcParamKey.description)=\(port)")
                    case .ipv4hint:
                        guard svcParamValueLength % 4 == 0 else {
                            offset += Int(rdlength)
                            throw DNSError.parsingError(DNSError.invalidData("invalid length for ipv4hint: \(svcParamValueLength)"))
                        }
                        
                        var ips: [String] = []
                        let count = (svcParamValueData.count / 4) - 1
                        
                        var ipOffset: Int = 0
                        for _ in 0...count {
                            let ipBytes = svcParamValueData[ipOffset..<ipOffset+4]
                            let ip = ResourceRecord.decodeIPv4(ipBytes)
                            ips.append(ip)
                            ipOffset += 4
                        }
                        
                        value.append(" \(svcParamKey.description)=\(ips.joined(separator: ","))")
                    case .ech:
                        let echData = svcParamValueData.base64EncodedString()
                        value.append(" \(svcParamKey.description)=\(echData)")
                    case .ipv6hint:
                        guard svcParamValueLength % 16 == 0 else {
                            offset += Int(rdlength)
                            throw DNSError.parsingError(DNSError.invalidData("invalid length for ipv6hint: \(svcParamValueLength)"))
                        }
                        
                        var ips: [String] = []
                        let count = (svcParamValueData.count / 16) - 1
                        
                        var ipOffset: Int = 0
                        for _ in 0...count {
                            let ipBytes = svcParamValueData.subdata(in: ipOffset..<ipOffset+16)
                            let ip = ResourceRecord.decodeIPv6(ipBytes)
                            ips.append(ip)
                            ipOffset += 16
                        }
                        
                        value.append(" \(svcParamKey.description)=\(ips.joined(separator: ","))")
                    case .dohpath:
                        guard let path = String(data: svcParamValueData, encoding: .utf8) else {
                            throw DNSError.invalidData("Failed to parse doh path")
                        }
                        
                        // TODO: validate the input and escape some characters
                        
                        value.append(" \(svcParamKey.description)=\(path)")
                    default: // case .unknown(_), .ohttp:
                        // ohttp should be empty
                        // https://www.rfc-editor.org/rfc/rfc9540.html#name-the-ohttp-svcparamkey
                        if let str = String(data: svcParamValueData, encoding: .utf8), str.isPrintable {
                            value.append(" \(svcParamKey.description)=\(str)")
                        } else {
                            value.append(" \(svcParamKey.description)=0x\(svcParamValueData.hexEncodedString())")
                        }
                    }
                    
                    offset += Int(svcParamValueLength)
                }
            }
            
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
            // https://datatracker.ietf.org/doc/html/rfc3597#section-5
            let value = "\\# \(rdlength) \(rdata.hexEncodedString())"
            
            self = ResourceRecord(name: domainName, ttl: ttl, Class: Class, type: type, value: value)
        }
    }
    
    /// Encodes a ResourceRecord into Data
    ///
    /// It uses DNS compression as defined in RFC1035
    /// - Parameters:
    ///   - messageLength: The length of the DNS message that has already been encoded
    ///   - nameOffsets: A dictionary where the keys are domains and the values are the position where it can be found in the data. This is required for DNS compression
    /// - Returns: The data representing the DNS record
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
        
        /// It is the position where the data ends, the current position of the "writer".
        /// It is used to know where to point to when compressing
        var offset = messageLength + bytes.count
        
        // Increase the offset by the length of the RDLength
        offset += 2
        
        var rdata: Data = Data()
        
        switch self.type {
        case .A:
            // let octets = self.value.split(separator: ".").compactMap { UInt8($0) }
            let octets = try ResourceRecord.encodeIPv4(self.value)
            guard octets.count == 4 else {
                throw DNSError.parsingError(DNSError.invalidData("Invalid A record IP: \(value)"))
            }
            rdata.append(contentsOf: octets)
        case .AAAA:
            let ipv6 = try ResourceRecord.encodeIPv6(self.value)
            
            rdata.append(contentsOf: ipv6)
        case .CNAME, .NS, .PTR:
            // rdlength offset +2 was here
            let domain = try DNSMessage.encodeDomainName(name: self.value, messageLength: offset, nameOffsets: &nameOffsets)
            offset += domain.count
            rdata.append(domain)
        case .MX:
            let parts = self.value.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let preference = UInt16(parts[0]) else {
                throw DNSError.parsingError(DNSError.invalidData("Invalid MX record value: \(value)"))
            }
            
            rdata.append(contentsOf: withUnsafeBytes(of: preference.bigEndian) { Data($0) })
            offset += 2
            let domain = try DNSMessage.encodeDomainName(name: String(parts[1]), messageLength: offset, nameOffsets: &nameOffsets)
            rdata.append(domain)
            offset += domain.count
        case .TXT:
            let txtBytes = Array(self.value.utf8)
            guard txtBytes.count <= 255 else {
                throw DNSError.parsingError(DNSError.invalidData("TXT record too long"))
            }
            rdata.append(UInt8(txtBytes.count))
            rdata.append(contentsOf: txtBytes)
        case .SOA:
            let values = value.split(separator: " ")
            guard values.count == 7 else {
                throw DNSError.invalidData("SOA record value must contain 7 values separated by space")
            }
            
            guard let serial = UInt32(values[2]), let refresh = UInt32(values[3]), let retry = UInt32(values[4]), let expire = UInt32(values[5]), let minimum = UInt32(values[6]) else {
                throw DNSError.invalidData("SOA record values must be convertible to UInt32")
            }
            
            let MNAME = String(values[0])
            let encodedMNAME = try DNSMessage.encodeDomainName(name: MNAME, messageLength: offset, nameOffsets: &nameOffsets)
            offset += encodedMNAME.count
            rdata.append(encodedMNAME)
            
            let RNAME = String(values[1])
            let encodedRNAME = try DNSMessage.encodeDomainName(name: RNAME, messageLength: offset, nameOffsets: &nameOffsets)
            rdata.append(encodedRNAME)
            offset += encodedRNAME.count
            
            rdata.append(contentsOf: withUnsafeBytes(of: serial.bigEndian) { Data($0) })
            offset += 4
            rdata.append(contentsOf: withUnsafeBytes(of: refresh.bigEndian) { Data($0) })
            offset += 4
            rdata.append(contentsOf: withUnsafeBytes(of: retry.bigEndian) { Data($0) })
            offset += 4
            rdata.append(contentsOf: withUnsafeBytes(of: expire.bigEndian) { Data($0) })
            offset += 4
            rdata.append(contentsOf: withUnsafeBytes(of: minimum.bigEndian) { Data($0) })
            offset += 4
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
        case .DS:
            let values = value.split(separator: " ")
            guard values.count == 4 else {
                throw DNSError.invalidData("DS record value must contain 4 values separated by space. Contains \(values.count) values")
            }
            
            guard let keyTag = UInt16(values[0]), let algorithm = UInt8(values[1]), let digestType = UInt8(values[2]) else {
                throw DNSError.invalidData("Failed to parse DS record")
            }
            
            guard digestType == 1 else {
                throw DNSError.invalidData("Digest Type for DS record not suported: \(digestType)")
            }
            
            rdata.append(contentsOf: withUnsafeBytes(of: keyTag.bigEndian) { Data($0) })
            offset += 2
            
            rdata.append(contentsOf: withUnsafeBytes(of: algorithm.bigEndian) { Data($0) })
            offset += 1
            
            rdata.append(contentsOf: withUnsafeBytes(of: digestType.bigEndian) { Data($0) })
            offset += 1
            
            let digest = try Data(hex: values[3...values.count-1].joined())
            rdata.append(contentsOf: digest)
            offset += digest.count
        case .SSHFP:
            let values = value.split(separator: " ")
            guard values.count == 3 else {
                throw DNSError.invalidData("SSHFP record value must contain 4 values separated by space. Contains \(values.count) values")
            }
            
            guard let algorithm = UInt8(values[0]), let fingerprintType = UInt8(values[1]) else {
                throw DNSError.invalidData("Failed to parse SSHFP record")
            }
            
            rdata.append(algorithm)
            offset += 1
            
            rdata.append(fingerprintType)
            offset += 1
            
            let fingerprint = try Data(hex: String(values[2]))
            offset += fingerprint.count
            rdata.append(contentsOf: fingerprint)
        case .RRSIG:
            let values = value.split(separator: " ")
            guard values.count == 9 else {
                throw DNSError.invalidData("RRSIG record value must contain 9 values separated by space. Contains \(values.count) values")
            }
            
            guard let typeCovered = UInt16(values[0]),
                  let algorithm = UInt8(values[1]),
                  let labels = UInt8(values[2]),
                  let originalTTL = UInt32(values[3]),
                  let signatureExpiration = UInt32(values[4]),
                  let signatureInception = UInt32(values[5]),
                  let keyTag = UInt16(values[6]),
                  let signature = Data(base64Encoded: String(values[8]))
            else {
                throw DNSError.invalidData("Failed to parse RRSIG record values")
            }
            
            let signerName = try QuestionSection.encodeDomainName(name: String(values[7]))
            
            rdata.append(contentsOf: withUnsafeBytes(of: typeCovered.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: algorithm.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: labels.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: originalTTL.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: signatureExpiration.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: signatureInception.bigEndian) { Data($0) })
            rdata.append(contentsOf: withUnsafeBytes(of: keyTag.bigEndian) { Data($0) })
            rdata.append(contentsOf: signerName)
            rdata.append(contentsOf: signature)
        case .NSEC:
            let values = value.split(separator: " ")
            guard values.count >= 2 else {
                throw DNSError.invalidData("DS record value must contain 4 values separated by space. Contains: \(values.count) values")
            }
            
            // encode the name with no compression
            let name = try QuestionSection.encodeDomainName(name: String(values[0]))
            rdata.append(name)
            offset += name.count
            
            // blockNumber → bitmap bytes
            var blocks: [UInt8: [UInt8]] = [:] // [UInt8: [UInt8]]()
            
            try values.dropFirst().forEach { value in
                var rawType: UInt16 = 0
                let strValue = String(value)
                guard let type = DNSRecordType(strValue) else {
                    throw DNSError.invalidData("Failed to parse NSEC record: unknown type: \(strValue)")
                }
                rawType = type.rawValue
                
                let block = UInt8(rawType / 256)
                let offset = Int(rawType % 256)
                let byteIndex = offset / 8
                let bitIndex = 7 - (offset % 8)
                
                var bitmap = blocks[block] ?? Array(repeating: 0, count: byteIndex + 1)
                if bitmap.count <= byteIndex {
                    bitmap += Array(repeating: 0, count: byteIndex - bitmap.count + 1)
                }
                
                bitmap[byteIndex] |= (1 << bitIndex)
                blocks[block] = bitmap
            }
            
            for block in blocks.keys.sorted() {
                let bitmap = blocks[block]!
                rdata.append(block)
                rdata.append(UInt8(bitmap.count))
                rdata.append(contentsOf: bitmap)
            }
        case .DNSKEY:
            let values = value.split(separator: " ")
            guard values.count == 4 else {
                throw DNSError.invalidData("DNSKEY record value must contain 4 values separated by space. Contains: \(values.count) values")
            }
            
            guard let flags = UInt16(values[0]), let Protocol = UInt8(values[1]), let algorithm = UInt8(values[2]), let publicKey = Data(base64Encoded: String(values[3])) else {
                throw DNSError.invalidData("Failed to parse DNSKEY record")
            }
            
            guard Protocol == 3 else {
                throw DNSError.invalidData("Protocol for DNSKEY record must be 3: \(Protocol)")
            }
            
            rdata.append(contentsOf: withUnsafeBytes(of: flags.bigEndian) { Data($0) })
            offset += 2
            
            rdata.append(Protocol.bigEndian)
            offset += 1
            
            rdata.append(algorithm.bigEndian)
            offset += 1
            
            rdata.append(contentsOf: publicKey)
            offset += publicKey.count
        case .SVCB, .HTTPS:
            let values = value.split(separator: " ")
            guard values.count >= 2 else {
                throw DNSError.invalidData("\(type.description) record value must at least contain 2 values separated by space. Contains: \(values.count) values")
            }
            
            guard let svcPriority = UInt16(values[0]) else {
                throw DNSError.invalidData("Failed to parse \(type.description) record")
            }
            
            rdata.append(contentsOf: withUnsafeBytes(of: svcPriority.bigEndian) { Data($0) })
            offset += 2
            
            let targetName = String(values[1])
            let bytes = try QuestionSection.encodeDomainName(name: targetName)
            rdata.append(bytes)
            
            // Each svcParam's value has items separated by a comma and there should be no space inside. Each param is separated by a space
            for param in values.dropFirst(2) {
                let keyVal = param.split(separator: "=")
                guard let svcParamKey = SVCParamKeys(String(keyVal[0])) else {
                    throw DNSError.invalidData("Invalid SVCParamKey: '\(keyVal[0])'")
                }
                let svcParamValue = String(keyVal[1])
                
                rdata.append(contentsOf: withUnsafeBytes(of: svcParamKey.rawValue.bigEndian) { Data($0) })
                var paramValue: Data = Data()
                
                switch svcParamKey {
                case .mandatory:
                    let items = svcParamValue.split(separator: ",")
                    for item in items {
                        guard let key = SVCParamKeys(String(item)) else {
                            throw DNSError.invalidData("Invalid mandatory SVCParamKey: '\(item)'")
                        }
                        paramValue.append(contentsOf: withUnsafeBytes(of: key.rawValue.bigEndian) { Data($0) })
                    }
                case .alpn:
                    let items = svcParamValue.split(separator: ",")
                    for item in items {
                        let val = Array(String(item).utf8)
                        paramValue.append(UInt8(val.count))
                        paramValue.append(contentsOf: val)
                    }
                case .noDefaultAlpn:
                    if !svcParamValue.isEmpty {
                        let data = try Data(hex: String(svcParamValue.dropFirst(2)))
                        paramValue.append(data)
                    }
                case .port:
                    guard let port = UInt16(svcParamValue) else {
                        throw DNSError.invalidData("Failed to parse SVCB port value")
                    }
                    paramValue.append(contentsOf: withUnsafeBytes(of: port.bigEndian) { Data($0) })
                case .ipv4hint:
                    let items = svcParamValue.split(separator: ",")
                    for item in items {
                        let bytes = try ResourceRecord.encodeIPv4(String(item))
                        paramValue.append(contentsOf: bytes)
                    }
                case .ech:
                    guard let bytes = Data(base64Encoded: svcParamValue) else {
                        throw DNSError.invalidData("Failed to parse SVCB ECH value")
                    }
                    paramValue.append(contentsOf: bytes)
                case .ipv6hint:
                    let items = svcParamValue.split(separator: ",")
                    for item in items {
                        let bytes = try ResourceRecord.encodeIPv6(String(item))
                        paramValue.append(contentsOf: bytes)
                    }
                case .dohpath:
                    paramValue.append(Data(svcParamValue.utf8))
                default: // case .unknown(_), .ohttp:
                    if svcParamValue.hasPrefix("0x") {
                        paramValue.append(try Data(hex: String(svcParamValue.dropFirst(2))))
                    } else {
                        paramValue.append(contentsOf: svcParamValue.utf8)
                    }
                }
                
                rdata.append(contentsOf: withUnsafeBytes(of: UInt16(paramValue.count).bigEndian) { Data($0) })
                rdata.append(paramValue)
            }
            
        default:
            // https://datatracker.ietf.org/doc/html/rfc3597#section-5
            /*
             The RDATA section of an RR of unknown type is represented as a
             sequence of white space separated words as follows:
             
             The special token \# (a backslash immediately followed by a hash
             sign), which identifies the RDATA as having the generic encoding
             defined herein rather than a traditional type-specific encoding.
             
             An unsigned decimal integer specifying the RDATA length in octets.
             
             Zero or more words of hexadecimal data encoding the actual RDATA
             field, each containing an even number of hexadecimal digits.
             
             a.example.   CLASS32     TYPE731         \# 6 abcd ef 01 23 45
             
             If the RDATA is of zero length, the text representation contains only
             the \# token and the single zero representing the length.
             
             b.example.   HS          TYPE62347       \# 0
             */
            
            let values = self.value.split(separator: " ")
            
            guard values.count >= 2, values.first == ("\\#"), let length = UInt16(values[1]) else {
                throw DNSError.invalidData("Encoding for \(type) not implemented and RDATA doesn't follow the format in rfc3597 section 5")
            }
            
            if length != 0 {
                let str = String(values.dropFirst(2).joined(separator: ""))
                rdata.append(try Data(hex: str))
            }
        }
        
        let rdlength: UInt16 = UInt16(rdata.count).bigEndian
        bytes.append(contentsOf: withUnsafeBytes(of: rdlength) { Data($0) })
        // The length of the RDLength is added to the offset before the switch
        bytes.append(rdata)
        
        return bytes
    }
    
    internal static func decodeIPv4(_ ipBytes: Data) -> String {
        let ip = ipBytes.map { String($0) }.joined(separator: ".")
        return ip
    }
    
    internal static func encodeIPv4(_ address: String) throws -> Data {
        let octets = address.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else {
            throw DNSError.parsingError(DNSError.invalidData("Invalid A record IP: \(address)"))
        }
        return Data(octets)
    }
    
    internal static func decodeIPv6(_ ipBytes: Data) -> String {
        // Convert every 2 bytes into one 16-bit block
        var segments: [String] = []
        for i in stride(from: 0, to: 16, by: 2) {
            let part = (UInt16(ipBytes[i]) << 8) | UInt16(ipBytes[i + 1])
            segments.append(String(format: "%x", part))
        }
        
        let ip = segments.joined(separator: ":")
        return ip
    }
    
    
    /// Encodes an IPv6 address into Data
    /// - Parameter address: The IPv6 address as a string
    /// - Returns: The Data that represents the IPv6 address
    internal static func encodeIPv6(_ address: String) throws -> Data {
        guard let ipv6 = IPv6Address(address) else {
            throw DNSError.parsingError(DNSError.invalidData("Invalid IPv6 address: \(address)"))
        }
        
        return ipv6.rawValue
    }
    
    /// Initializes a Resource Record from a string
    /// - Parameter description: A single line with the Name, TTL, Class, Type, and Value separated by a space
    public init?(_ description: String) {
        let values = description.split(separator: " ")
        guard values.count >= 5 else { return nil }
        
        guard let ttl = UInt32(values[1]), let Class = DNSClass(String(values[2])), let type = DNSRecordType(String(values[3])) else {
            return nil
        }
        
        self.name = String(values[0])
        self.ttl = ttl
        self.Class = Class
        self.type = type
        value = values[4...].joined(separator: " ")
    }
    
    /// Returns a string with the Name, TTL, Class, Type, and Value separated by a space
    public var description: String {
        return "\(name) \(ttl) \(Class.description) \(type.description) \(value)"
    }
    
    public static func ==(lhs: ResourceRecord, rhs: ResourceRecord) -> Bool {
        return lhs.name == rhs.name && lhs.ttl == rhs.ttl && lhs.Class == rhs.Class && lhs.type == rhs.type && lhs.value == rhs.value
    }
}
