//
//  ResourceRecord.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The data format used for the answer, authority, and additional sections of a DNS packet.
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
        let (domainName, domainLength) = DNSClient.parseDomainName(data: data, offset: offset)
        // print("[decodeResourceRecord] domain name: \(domainName), length: \(domainLength). at offset: \(offset)")
        offset += domainLength
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 10 <= data.count else {
            // print("[decodeResourceRecord] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.invalidData("Offset over bounds for TYPE, CLASS, TTL, and RDLENGTH")
        }
        
        let rawType = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        guard let type = DNSRecordType(rawValue: rawType) else {
            // print("[decodeResourceRecord] Failed to parse TYPE. offset: \(offset)")
            throw DNSError.parsingError(DNSError.invalidData("Failed to parse TYPE: '\(rawType)'"))
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
        
        if type == .OPT {
            guard offset + Int(rdlength) <= data.count else {
                // print("Failed to parse OPT record: offset out of bounds")
                offset += Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("Failed to parse OPT record: offset out of bounds"))
            }

            let start = offset
            // https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
            //
            // +------------+--------------+------------------------------+
            // | Field Name | Field Type   | Description                  |
            // +------------+--------------+------------------------------+
            // | NAME       | domain name  | MUST be 0 (root domain)      |
            // | TYPE       | u_int16_t    | OPT (41)                     |
            // | CLASS      | u_int16_t    | requestor's UDP payload size |
            // | TTL        | u_int32_t    | extended RCODE and flags     |
            // | RDLEN      | u_int16_t    | length of all RDATA          |
            // | RDATA      | octet stream | {attribute,value} pairs      |
            // +------------+--------------+------------------------------+
            //
            
            // if domainName != "" { }
            
            // TTL Format:
            //
            //           +0 (MSB)                            +1 (LSB)
            // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
            //  0: |         EXTENDED-RCODE        |            VERSION        |
            // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
            // 2: | DO|                           Z                            |
            // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
            //
            
            /// Forms the upper 8 bits of extended 12-bit RCODE (together with the 4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0 indicates that an unextended RCODE is in use (values 0 through 15).
            let extendedRcode = UInt8((ttl & 0xFF00_0000) >> 24)
            /// Indicates the implementation level of the setter.  Full conformance with this specification is indicated by version '0'.
            ///
            /// Requestors are encouraged to set this to the lowest implemented level capable of expressing a transaction, to minimise the responder and network load of discovering the greatest common implementation level between requestor and responder.
            /// A requestor's version numbering strategy MAY ideally be a run-time configuration option.
            /// If a responder does not implement the VERSION level of the request, then it MUST respond with RCODE=BADVERS.
            /// All responses MUST be limited in format to the VERSION level of the request, but the VERSION of each response SHOULD be the highest implementation level of the responder.  In this way, a requestor will learn the implementation level of a responder as a side effect of every response, including error responses and including RCODE=BADVERS.
            let ednsVersion = UInt8((ttl & 0x00FF_0000) >> 16)
            /// Set to zero by senders and ignored by receivers, unless modified in a subsequent specification.
            let zField = UInt16(ttl & 0x0000_FFFF)

            /// DNSSEC OK bit as defined by [RFC3225](https://www.rfc-editor.org/rfc/rfc3225).
            let doBit = (zField & 0x8000) != 0
            
            // var rdataOffset = 0
            
            var options: [String] = []
            
            let end = start + Int(rdlength)
            while offset + 4 <= end {
                // Read OPTION-CODE
                let rawOptionCode = data.subdata(in: offset..<offset+2).withUnsafeBytes {
                    $0.load(as: UInt16.self).bigEndian
                }
                offset += 2
                
                // Read OPTION-LENGTH
                let optionLength = data.subdata(in: offset..<offset+2).withUnsafeBytes {
                    $0.load(as: UInt16.self).bigEndian
                }
                offset += 2
                
                // Check that the data is within the length
                guard offset + Int(optionLength) <= end else {
                    throw DNSError.parsingError(DNSError.invalidData("edns option length out of bounds"))
                }
                
                // Read OPTION-DATA
                let optionData = data.subdata(in: offset..<offset+Int(optionLength))
                offset += Int(optionLength)
                
                guard let optionCode = EDNSOptionCode(rawValue: rawOptionCode) else {
                    throw DNSError.invalidData("invalid EDNS option code: '\(rawOptionCode)'")
                }
                
                let decoded = ResourceRecord.decodeEDNSOption(code: optionCode, data: optionData)

                options.append("\(optionCode.description): \(decoded)")
            }
            
            let value: String = "EXT_RCODE=\(extendedRcode), VERSION=\(ednsVersion), DO=\(doBit)\nOPTIONS: \(options.joined(separator: "\n"))"
            
            self = ResourceRecord(name: domainName, ttl: 0, Class: .unknown, type: type, value: value)
            return
        } // if type == OPT ends
        
        guard let Class = DNSClass(rawValue: rawClass) else {
            // print("[decodeResourceRecord] Failed to parse CLASS. offset: \(offset)")
            throw DNSError.invalidData("Failed to parse CLASS: '\(rawClass)'")
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

            let (domain, _) = DNSClient.parseDomainName(data: data, offset: offset + 2)
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
            let (domain, _) = DNSClient.parseDomainName(data: data, offset: offset)
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

            let (target, targetLen) = DNSClient.parseDomainName(data: data, offset: offset)
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
            let (mname, mnameLen) = DNSClient.parseDomainName(data: data, offset: offset)
            offset += mnameLen

            // Parse RNAME
            let (rname, rnameLen) = DNSClient.parseDomainName(data: data, offset: offset)
            offset += rnameLen

            // Check remaining size
            let remaining = start + Int(rdlength) - offset
            guard remaining >= 20 else {
                // print("SOA RDATA too short after domain names")
                offset = start + Int(rdlength)
                throw DNSError.parsingError(DNSError.invalidData("soa rdata too short after domain names"))
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
    
    /// Decodes an EDNS Option and returns it as a string
    /// - Parameters:
    ///   - code: The EDNS Option Code
    ///   - data: The data representing the EDNS Option Code's data
    /// - Returns: A string with the contents of the EDNS Option Code
    private static func decodeEDNSOption(code: EDNSOptionCode, data: Data) -> String {
        switch code {
        case .COOKIE:
            if data.count < 8 {
                return "Invalid COOKIE option (too short)"
            }
            
            let clientCookie = data.subdata(in: 0..<8).map { String(format: "%02x", $0) }.joined()
            let serverCookie = data.count > 8 ? data.subdata(in: 8..<data.count).map { String(format: "%02x", $0) }.joined() : "None"
            
            return "Client=\(clientCookie), Server=\(serverCookie)"
        case .ClientSubnet:
            guard data.count >= 4 else { return "Invalid Client Subnet option (too short)" }
            print("[decodeEDNSOption]: ClientSubnet. data: \(data.hexEncodedString())")
            
            let family = UInt16(bigEndian: data.subdata(in: 0..<2).withUnsafeBytes { $0.load(as: UInt16.self) })
            let sourceMask = data[2]
            let scopeMask = data[3]
            
            let addressBytes = data.subdata(in: 4..<data.count)
            
            let ipString: String
            if family == 1 {
                
                // IPv4
                // Adds missing octets set to zero to make sure that they are printed
                let paddedAddress = addressBytes + Data(repeating: 0, count: max(0, 4 - addressBytes.count))
                ipString = paddedAddress.map { String($0) }.joined(separator: ".")
                // ipString = addressBytes.prefix(4).map { String($0) }.joined(separator: ".")
            } else if family == 2 {
                // IPv6
                // Adds missing hextets set to zero to make sure that they are printed
                let paddedAddress = addressBytes + Data(repeating: 0, count: max(0, 16 - addressBytes.count))
                
                var segments: [String] = []
                for i in stride(from: 0, to: paddedAddress.count, by: 2) {
                    let part = (UInt16(paddedAddress[i]) << 8) | UInt16(paddedAddress[i + 1])
                    segments.append(String(format: "%x", part))
                }
                
                ipString = segments.joined(separator: ":")
            } else {
                ipString = "Failed to parse address. '\(addressBytes.hexEncodedString())'"
            }
            
            return "Family=\(family), SourceMask=\(sourceMask), ScopeMask=\(scopeMask), IP=\(ipString)"
        case .KeepAlive:
            #warning("needs testing")
            guard data.count == 2 else { return "Invalid KEEPALIVE option" }
            
            let timeout = UInt16(bigEndian: data.withUnsafeBytes { $0.load(as: UInt16.self) })
            return "Timeout=\(timeout) ms"
        case .Padding:
            #warning("needs testing")
            return "Padding (\(data.count) bytes)"
        default:
            if let str = String(data: data, encoding: .utf8), str.isPrintable {
                return str
            }
            // fallback to hex representation
            return data.map { String(format: "%02x", $0) }.joined(separator: " ")
        }
    }

    
    // Gets complicated with compression
    /*
    public func toData() throws -> Data {
        var bytes: Data = DNSClient.encodeDomainName(name: self.name)
        
        var qtype: UInt16 = type.rawValue.bigEndian
        bytes.append(Data(bytes: &qtype, count: 2))
        
        var qclass: UInt16 = Class.rawValue.bigEndian
        bytes.append(Data(bytes: &qclass, count: 2))
        
        var ttl: UInt32 = ttl.bigEndian
        bytes.append(Data(bytes: &ttl, count: 4))
        
        guard let rdata: Data = value.data(using: .utf8) else {
            throw DNSError.parsingError(DNSError.invalidData)
        }
        
        var rdlength: UInt16 = UInt16(rdata.count).bigEndian
        bytes.append(Data(bytes: &rdlength, count: 2))
        
        bytes.append(rdata)
        
        return bytes
    }*/
    
    /// Returns a string with the Name, TTL, Class, Type, and Value
    public var description: String {
        return "\(name) \(ttl) \(Class.displayName) \(type) \(value)"
    }
    
    public static func ==(lhs: ResourceRecord, rhs: ResourceRecord) -> Bool {
        return lhs.name == rhs.name && lhs.ttl == rhs.ttl && lhs.Class == rhs.Class && lhs.type == rhs.type && lhs.value == rhs.value
    }
}

/// The EDNS Options Codes
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
enum EDNSOptionCode: UInt16 {
    case reserved = 0
    case LLQ = 1
    case NSID = 3
    case DAU = 5
    case DHU = 6
    case N3U = 7
    case ClientSubnet = 8
    case COOKIE = 10
    case KeepAlive = 11
    case Padding = 12
    case ExtendedDNSError = 15
    case unknown
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let type = try container.decode(UInt16.self)
        
        self.init(rawValue: type)!
    }
    
    /// A short user-friendly string that describes the EDNS Option Code
    public var description: String {
        switch self {
        case .reserved: return "RESERVED"
        case .LLQ: return "LLQ"
        case .NSID: return "NSID"
        case .DAU: return "DAU"
        case .DHU: return "DHU"
        case .N3U: return "N3U"
        case .ClientSubnet: return "Client Subnet"
        case .COOKIE: return "Cookie"
        case .KeepAlive: return "KeepAlive"
        case .Padding: return "Padding"
        case .ExtendedDNSError: return "ExtendedDNSError"
        case .unknown: return "Unkown: '\(self.rawValue)'"
        }
    }
    
    public static func == (lhs: EDNSOptionCode, rhs: EDNSOptionCode) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
