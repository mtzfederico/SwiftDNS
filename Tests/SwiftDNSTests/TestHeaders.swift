//
//  TestHeaders.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestHeaders {

    @Test func testParseHeader() throws {
        var offset = 0
        // let data: Data = Data([0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]) // Mock DNS response data
        let data: Data = Data([0x7c, 0xa1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x62, 0x61, 0x6e, 0x64, 0x61, 0x61, 0x6e, 0x63, 0x68, 0x61, 0x02, 0x65, 0x75, 0x00, 0x00, 0x1c, 0x00, 0x01])
        
        let header = try DNSHeader(data: data, offset: &offset)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x7Ca1, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(header == expectedHeader)
    }
    
    
    @Test func testDecodeHeader0() throws {
        let data: Data = Data([
            0x12, 0x34,  // Transaction ID
            0x01, 0x80,  // Flags (QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=000, RCODE=0) --> 0 0000 0 0 1 1 000 0000
            0x00, 0x01,  // QDCOUNT (1 question)
            0x00, 0x00,  // ANCOUNT (0 answers)
            0x00, 0x00,  // NSCOUNT (0 authority records)
            0x00, 0x00,  // ARCOUNT (0 additional records)

            // QNAME (example.com)
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,  // "example"
            0x03, 0x63, 0x6F, 0x6D,  // "com"
            0x00,  // End of QNAME

            0x00, 0x01,  // QTYPE (A record)
            0x00, 0x01   // QCLASS (IN class)
        ])
        
        var offset = 0
        let header = try DNSHeader(data: data, offset: &offset)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x1234, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(header == expectedHeader)
        
        // ResourceRecord(name: "example.com", type: 0, CLASS: 0, TTL: 0, RDLENGTH: 0)
    }

}

