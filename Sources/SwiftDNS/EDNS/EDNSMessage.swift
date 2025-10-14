//
//  EDNSMessage.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-02
// 

import Foundation

/// The EDNS data as defined in [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)
public struct EDNSMessage: Sendable {
    /// The max UDP payload size
    ///
    /// The default value is 1232 bytes as recommended by [DNS Flag Day 2020](https://www.dnsflagday.net/2020/)
    ///
    /// In [RFC1035](https://www.rfc-editor.org/rfc/rfc1035), the limit is 512 bytes
    public let udpPayloadSize: UInt16
    public let extendedRcode: UInt8
    public let version: UInt8
    public let zField: UInt16
    /// Used to indicate to the server to send DNSSEC Resource Records as defined in [RFC 3225](https://www.rfc-editor.org/rfc/rfc3225)
    public let doBit: Bool
    /// The EDNS options
    public let options: [EDNSOption]
    
    public init(extendedRcode: UInt8, version: UInt8, zField: UInt16, doBit: Bool, options: [EDNSOption], udpPayloadSize: UInt16 = 1232) {
        self.udpPayloadSize = udpPayloadSize
        self.extendedRcode = extendedRcode
        self.version = version
        self.zField = zField
        self.doBit = doBit
        self.options = options
    }
    
    public init(data: Data, offset: inout Int) throws {
        let (domainName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
        offset += domainLength
        
        if domainLength != 1 {
            throw DNSError.invalidData("OPT record has a non-null label: '\(domainName)'")
        }
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 10 <= data.count else {
            offset += 10
            // print("[decodeResourceRecord] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.invalidData("Offset (\(offset)) over bounds (\(data.count)) for TYPE, CLASS, TTL, and RDLENGTH")
        }
        
        let rawType = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        if rawType != 41 {
            throw DNSError.invalidData("Record Type is not OPT: '\(rawType)'")
        }
        
        offset += 2 // type
        
        udpPayloadSize = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2 // udpPayloadSize (the class)
        
        let ttl = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        offset += 4 // ttl
        
        let rdlength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2 // rdLength
        
        guard offset + Int(rdlength) <= data.count else {
            offset += Int(rdlength)
            throw DNSError.parsingError(DNSError.invalidData("Failed to parse OPT record: offset (\(offset + Int(rdlength))) out of bounds (\(data.count))"))
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
        extendedRcode = UInt8((ttl & 0xFF00_0000) >> 24)
        /// Indicates the implementation level of the setter.  Full conformance with this specification is indicated by version '0'.
        ///
        /// Requestors are encouraged to set this to the lowest implemented level capable of expressing a transaction, to minimise the responder and network load of discovering the greatest common implementation level between requestor and responder.
        /// A requestor's version numbering strategy MAY ideally be a run-time configuration option.
        /// If a responder does not implement the VERSION level of the request, then it MUST respond with RCODE=BADVERS.
        /// All responses MUST be limited in format to the VERSION level of the request, but the VERSION of each response SHOULD be the highest implementation level of the responder.  In this way, a requestor will learn the implementation level of a responder as a side effect of every response, including error responses and including RCODE=BADVERS.
        version = UInt8((ttl & 0x00FF_0000) >> 16)
        /// Set to zero by senders and ignored by receivers, unless modified in a subsequent specification.
        zField = UInt16(ttl & 0x0000_FFFF)

        /// DNSSEC OK bit as defined by [RFC3225](https://www.rfc-editor.org/rfc/rfc3225).
        doBit = (zField & 0x8000) != 0
        
        var options: [EDNSOption] = []
        
        let end = start + Int(rdlength)
        while offset + 4 <= end {
            options.append(try EDNSOption(data: data, offset: &offset))
        }
        
        self.options = options
    }
    
    public func toData() throws -> Data {
        var data = try QuestionSection.encodeDomainName(name: "")
        
        let qtype: UInt16 = 41
        data.append(contentsOf: withUnsafeBytes(of: qtype.bigEndian) { Data($0) })
        data.append(contentsOf: withUnsafeBytes(of: udpPayloadSize.bigEndian) { Data($0) })
        
        var zField: UInt16 = self.zField
        
        // Set or clear the DO bit (bit 15)
        if doBit {
            // Set DO bit (bit 15) to 1. 0x8000 == 10000000 00000000
            zField = zField | 0x8000

        } else {
            // Set DO bit to 0
            // Uses AND NOT
            zField = zField & (~0x8000)
        }
        
        let ttl: UInt32 = (UInt32(extendedRcode) << 24) | (UInt32(version) << 16) | UInt32(zField)
        data.append(contentsOf: withUnsafeBytes(of: ttl.bigEndian) { Data($0) })
        
        var rdata: Data = Data()
        
        for opt in options {
            let optionData = try opt.toData()
            rdata.append(optionData)
        }
        
        let rdlength: UInt16 = UInt16(rdata.count).bigEndian
        data.append(contentsOf: withUnsafeBytes(of: rdlength) { Data($0) })
        data.append(rdata)
        
        return data
    }
    
    var description: String {
        var description = "EXT_RCODE=\(extendedRcode), VERSION=\(version), DO=\(doBit), OPTIONS:\n"
        for opt in options {
            description += "\(opt.description)\n"
        }
        return description
    }
    
    public static func ==(lhs: EDNSMessage, rhs: EDNSMessage) -> Bool {
        return lhs.extendedRcode == rhs.extendedRcode && lhs.version == rhs.version && lhs.zField == rhs.zField && lhs.doBit == rhs.doBit && lhs.options == rhs.options
    }
}
