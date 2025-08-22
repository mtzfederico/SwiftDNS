//
//  DNSHeader.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

public struct DNSHeader {
    /// A 16 bit identifier assigned to the query.  This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    public let id: UInt16
    /// The dns flags
    public let flags: DNSFlags
    /// An unsigned 16 bit integer specifying the number of entries in the question section.
    public let QDCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of resource records in the answer section.
    public let  ANCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    public let  NSCOUNT: UInt16
    /// An unsigned 16 bit integer specifying the number of resource records in the additional records section.
    public let  ARCOUNT: UInt16
    
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
        self.flags =  DNSFlags(from: try data.readUInt16(at: 2))
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
    
    /// Represents the Flags in the header
    public struct DNSFlags {
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
        /// Authenticated Data (DNSSEC RFC4035)
        // public var ad: UInt16 = 0
        /// Checking Disabled (DNSSEC RFC4035)
        // public var cd: UInt16 = 0
        /// Response code - this 4 bit field is set as part of responses.  The values have the following interpretation:
        ///
        /// * 0               No error condition
        /// * 1               Format error - The name server was unable to interpret the query.
        /// * 2               Server failure - The name server wasunable to process this query due to a problem with the name server.
        /// * 3               Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
        /// * 4               Not Implemented - The name server does not support the requested kind of query.
        /// * 5               Refused - The name server refuses to perform the specified operation for policy reasons. For example, a name server may not wish to provide the information to the particular requester, or a name server
        ///           may not wish to perform a particular operation (e.g., zone transfer) for particular data.
        /// * 6-15          reserved for future use
        public var rcode: UInt16 = 0
        
        public init(qr: UInt16, opcode: UInt16, aa: UInt16, tc: UInt16, rd: UInt16, ra: UInt16, rcode: UInt16) {
            self.qr = qr
            self.opcode = opcode
            self.aa = aa
            self.tc = tc
            self.rd = rd
            self.ra = ra
            // self.ad = ad
            // self.cd = cd
            self.rcode = rcode
        }

        public init(from raw: UInt16) {
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
            rcode  = (raw & 0x000F)
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
            raw |= (rcode  & 0xF)
            return raw
        }
        
        public static func ==(lhs: DNSFlags, rhs: DNSFlags) -> Bool {
            return lhs.qr == rhs.qr && lhs.opcode == rhs.opcode && lhs.aa == rhs.aa && lhs.tc == rhs.tc && lhs.rd == rhs.rd && lhs.ra == rhs.ra && lhs.rcode == rhs.rcode
        }
    }
}
