//
//  DNSHeader.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// The Hedaer section of a DNS packet
public struct DNSHeader: Sendable {
    /// A 16 bit identifier assigned to the query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    public let id: UInt16
    /// The dns flags
    public let flags: DNSFlags
    /// An unsigned 16 bit integer specifying the number of entries in the question section.
    public let QDCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of resource records in the answer section.
    public let ANCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    public let NSCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of resource records in the additional records section.
    public let ARCOUNT: UInt16
    
    public init(id: UInt16, flags: DNSFlags, QDCOUNT: UInt16, ANCOUNT: UInt16, NSCOUNT: UInt16, ARCOUNT: UInt16) {
        self.id = id
        self.flags = flags
        self.QDCOUNT = QDCOUNT
        self.ANCOUNT = ANCOUNT
        self.NSCOUNT = NSCOUNT
        self.ARCOUNT = ARCOUNT
    }
    
    public init(data: Data, offset: inout Int) throws {
        // Extracting DNS header fields from the raw data
        self.id = try data.readUInt16(at: 0)
        self.flags =  try DNSFlags(from: try data.readUInt16(at: 2))
        self.QDCOUNT = try data.readUInt16(at: 4)
        self.ANCOUNT = try data.readUInt16(at: 6)
        self.NSCOUNT = try data.readUInt16(at: 8)
        self.ARCOUNT = try data.readUInt16(at: 10)
        
        offset += 12
    }
    
    public func toData() -> Data {
        var bytes = Data()
        
        bytes.append(contentsOf: withUnsafeBytes(of: id.bigEndian) { Data($0) })
        bytes.append(contentsOf: withUnsafeBytes(of: flags.toRaw().bigEndian) { Data($0) })
        bytes.append(contentsOf: withUnsafeBytes(of: QDCOUNT.bigEndian) { Data($0) })
        bytes.append(contentsOf: withUnsafeBytes(of: ANCOUNT.bigEndian) { Data($0) })
        bytes.append(contentsOf: withUnsafeBytes(of: NSCOUNT.bigEndian) { Data($0) })
        bytes.append(contentsOf: withUnsafeBytes(of: ARCOUNT.bigEndian) { Data($0) })
        
        return bytes
    }
    
    /// Returns a string describing the DNS Header
    public func description() -> String {
        return "ID: 0x\(String(format:"%02x", id)), \(flags), QDCOUNT: \(QDCOUNT), ANCOUNT: \(ANCOUNT), NSCOUNT: \(NSCOUNT), ARCOUNT: \(ARCOUNT)"
    }
    
    public static func == (lhs: DNSHeader, rhs: DNSHeader) -> Bool {
        return lhs.id == rhs.id && lhs.flags == rhs.flags && lhs.QDCOUNT == rhs.QDCOUNT && lhs.ANCOUNT == rhs.ANCOUNT && lhs.NSCOUNT == rhs.NSCOUNT && lhs.ARCOUNT == rhs.ARCOUNT
    }
    
    /// The Flags in the DNS header
    public struct DNSFlags: Sendable {
        /// A one bit field that specifies whether this message is a query (0), or a response (1).
        public var qr: UInt16 = 0
        /// A four bit field that specifies kind of query in this message.  This value is set by the originator of a query and copied into the response.  The values are:
        /// 0               a standard query (QUERY)
        /// 1               an inverse query (IQUERY)
        /// 2               a server status request (STATUS)
        /// 3-15          reserved for future use
        public var opcode: UInt16 = 0
        /// Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.
        public var aa: UInt16 = 0
        /// Truncation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
        public var tc: UInt16 = 0
        /// Recursion Desired - this bit may be set in a query and is copied into the response.  If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
        public var rd: UInt16 = 0
        /// Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
        public var ra: UInt16 = 0
        /// Reserved for future use. 3 bits long.  Must be zero in all queries and responses.
        public var z: UInt16 = 0
        /// Response code - this 4 bit field is set as part of responses.
        public var rcode: DNSResponseCode = .NoError
        
        public init(qr: UInt16, opcode: UInt16, aa: UInt16, tc: UInt16, rd: UInt16, ra: UInt16, rcode: DNSResponseCode, z: UInt16 = 0) throws {
            self.qr = qr
            self.opcode = opcode
            self.aa = aa
            self.tc = tc
            self.rd = rd
            self.ra = ra
            // Z is 3 bits long
            guard z <= 7 else {
                throw DNSError.invalidData("z value too big")
            }
            self.z = z
            
            self.rcode = rcode
        }
        
        public init(qr: UInt16, opcode: UInt16, aa: UInt16, tc: UInt16, rd: UInt16, ra: UInt16, rcode: UInt16, z: UInt16 = 0) throws {
            self.qr = qr
            self.opcode = opcode
            self.aa = aa
            self.tc = tc
            self.rd = rd
            self.ra = ra
            // Z is 3 bits long
            guard z <= 7 else {
                throw DNSError.invalidData("z value too big")
            }
            self.z = z
            
            self.rcode = DNSResponseCode(rcode)
        }

        public init(from raw: UInt16) throws {
            /*
                                            1  1  1  1  1  1
              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             */
            
            // 1 bit
            // 1000 0000 0000 0000
            qr     = (raw & 0x8000) >> 15
            // 4 bits
            // 0111 1000 0000 0000
            opcode = (raw & 0x7800) >> 11
            // 1 bit
            // 0000 0100 0000 0000
            aa     = (raw & 0x0400) >> 10
            // 1 bit
            // 0000 0010 0000 0000
            tc     = (raw & 0x0200) >> 9
            // 1 bit
            // 0000 0001 0000 0000
            rd     = (raw & 0x0100) >> 8
            // 1 bit
            // 0000 0000 1000 0000
            ra     = (raw & 0x0080) >> 7
            // 3 bit
            // 0000 0000 0111 0000
            z      = (raw & 0x0070) >> 4
            // 4 bit
            // 0000 0000 0000 1111
            let rawRcode: UInt16 = (raw & 0x000F)
            rcode = DNSResponseCode(rawRcode)
        }

        /// Returns the flags as a UInt16
        public func toRaw() -> UInt16 {
            var raw: UInt16 = 0
            raw |= (qr     & 0x1) << 15
            raw |= (opcode & 0xF) << 11
            raw |= (aa     & 0x1) << 10
            raw |= (tc     & 0x1) << 9
            raw |= (rd     & 0x1) << 8
            raw |= (ra     & 0x1) << 7
            raw |= (z      & 0x7) << 4
            raw |= (rcode.rawValue  & 0xF)
            return raw
        }
        
        public static func ==(lhs: DNSFlags, rhs: DNSFlags) -> Bool {
            return lhs.qr == rhs.qr && lhs.opcode == rhs.opcode && lhs.aa == rhs.aa && lhs.tc == rhs.tc && lhs.rd == rhs.rd && lhs.ra == rhs.ra && lhs.rcode == rhs.rcode
        }
    }
}

/// The DNS RCode as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
public enum DNSResponseCode: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    case NoError // = 0
    case FormErr // = 1
    case ServFail // = 2
    case NXDomain // = 3
    case NotImp // = 4
    case Refused // = 5
    case YXDomain // = 6
    case YXRRSet // = 7
    case NXRRSet // = 8
    case NotAuth // = 9
    case NotZone // = 10
    case DSOTYPENI // = 11
    // The next ones are in EDNS Extended Error
    case BADSIG // = 16
    case BADKEY // = 17
    case BADTIME // = 18
    case BADMODE // = 19
    case BADNAME // = 20
    case BADALG // = 21
    case BADTRUNC // = 22
    case BADCOOKIE // = 23
    case unknown(UInt16)
    
    public init(_ value: UInt16) {
        switch value {
        case 0:
            self = .NoError
        case 1:
            self = .FormErr
        case 2:
            self = .ServFail
        case 3:
            self = .NXDomain
        case 4:
            self = .NotImp
        case 5:
            self = .Refused
        case 6:
            self = .YXDomain
        case 7:
            self = .YXRRSet
        case 8:
            self = .NXRRSet
        case 9:
            self = .NotAuth
        case 10:
            self = .NotZone
        case 11:
            self = .DSOTYPENI
        case 16:
            self = .BADSIG
        case 17:
            self = .BADKEY
        case 18:
            self = .BADTIME
        case 19:
            self = .BADMODE
        case 20:
            self = .BADNAME
        case 21:
            self = .BADALG
        case 22:
            self = .BADTRUNC
        case 23:
            self = .BADCOOKIE
        default:
            self = .unknown(value)
        }
    }
    
    public var rawValue: UInt16 {
        switch self {
        case .NoError:
            return 0
        case .FormErr:
            return 1
        case .ServFail:
            return 2
        case .NXDomain:
            return 3
        case .NotImp:
            return 4
        case .Refused:
            return 5
        case .YXDomain:
            return 6
        case .YXRRSet:
            return 7
        case .NXRRSet:
            return 8
        case .NotAuth:
            return 9
        case .NotZone:
            return 10
        case .DSOTYPENI:
            return 11
        case .BADSIG:
            return 16
        case .BADKEY:
            return 17
        case .BADTIME:
            return 18
        case .BADMODE:
            return 19
        case .BADNAME:
            return 20
        case .BADALG:
            return 21
        case .BADTRUNC:
            return 22
        case .BADCOOKIE:
            return 23
        case .unknown(let value):
            return value
        }
    }
    
    /// A short string that represents the RCode
    ///
    /// Unknown records are represented as RCODE + unsigned integer such as RCODE123
    public var description: String {
        switch self {
        case .NoError:
            return "NoError"
        case .FormErr:
            return "FormErr"
        case .ServFail:
            return "ServFail"
        case .NXDomain:
            return "NXDomain"
        case .NotImp:
            return "NotImp"
        case .Refused:
            return "Refused"
        case .YXDomain:
            return "YXDomain"
        case .YXRRSet:
            return "YXRRSet"
        case .NXRRSet:
            return "NXRRSet"
        case .NotAuth:
            return "NotAuth"
        case .NotZone:
            return "NotZone"
        case .DSOTYPENI:
            return "DSOTYPENI"
        case .BADSIG:
            return "BADSIG"
        case .BADKEY:
            return "BADKEY"
        case .BADTIME:
            return "BADTIME"
        case .BADMODE:
            return "BADMODE"
        case .BADNAME:
            return "BADNAME"
        case .BADALG:
            return "BADALG"
        case .BADTRUNC:
            return "BADTRUNC"
        case .BADCOOKIE:
            return "BADCOOKIE"
        case .unknown(let value):
            return "RCODE\(value)"
        }
    }
    
    /// A  user-friendly string that describes the RCode's meaning
    public var debugDescription: String {
        switch self {
        case .NoError:
            return "No Error"
        case .FormErr:
            return "Format Error"
        case .ServFail:
            return "Server Failure"
        case .NXDomain:
            return "Non-Existent Domain"
        case .NotImp:
            return "Not Implemented"
        case .Refused:
            return "Query Refused"
        case .YXDomain:
            return "Name Exists when it should not"
        case .YXRRSet:
            return "RR Set Exists when it should not"
        case .NXRRSet:
            return "RR Set that should exist does not"
        case .NotAuth:
            return "Server Not Authoritative for zone"
        case .NotZone:
            return "Name not contained in zone"
        case .DSOTYPENI:
            return "DSO-TYPE Not Implemented"
        case .BADSIG:
            return "TSIG Signature Failure"
        case .BADKEY:
            return "Key not recognized"
        case .BADTIME:
            return "Signature out of time window"
        case .BADMODE:
            return "Bad TKEY Mode"
        case .BADNAME:
            return "Duplicate key name"
        case .BADALG:
            return "Algorithm not supported"
        case .BADTRUNC:
            return "Bad Truncation"
        case .BADCOOKIE:
            return "Bad/missing Server Cookie"
        case .unknown(let value):
            return "unknown. Value: '\(value)'"
        }
    }
    
    /// A user friendly string that shows the error's name and a short description
    ///
    /// Format "name - short description"
    ///
    /// You can get the values separately using description and debugDescription respectively
    public var displayString: String {
        return "\(self.description) - \(self.debugDescription)"
    }
    
    public static func ==(lhs: DNSResponseCode, rhs: DNSResponseCode) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
