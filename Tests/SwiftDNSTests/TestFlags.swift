//
//  TestFlags.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 


import Testing
import Foundation
@testable import SwiftDNS

struct TestFlags {
    /*
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    @Test func testDNSFlags0() throws {
        // 0 0000 0 0 1 1 000 0000
        let rawFlags: UInt16 = 0x180
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        // this is a response for a standard query, it is not authoritative, no truncation, recursion was desired and available, no error from server
        let expectedFlags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
    }
    
    @Test func testDNSFlags1() throws {
        // 1 0000 0 0 0 1 000 0000
        let rawFlags: UInt16 = 0x8080
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        // this is a response for an inverse query (rDNS), it is not authoritative, no truncation, recursion was desired and available, no error from server
        let expectedFlags = DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 1, rcode: 0)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
    }
    
    @Test func testDNSFlags2() throws {
        // 0 0010 0 0 1 0 000 0000
        let rawFlags: UInt16 = 0x1100
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        // a server status request
        let expectedFlags = DNSHeader.DNSFlags(qr: 0, opcode: 2, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
        
        // print("encodedFlags: \(encodedFlags) --> 0x\(String(format:"%02x", encodedFlags))")
    }
    
    @Test func testDNSFlags3() throws {
        // 0 0000 0 0 1 0 000 0000
        // let rawFlags: UInt16 = 0x100
        let rawFlags: Data = Data([0x01, 0x00])
        let parsedFlags = try DNSHeader.DNSFlags(from: try rawFlags.readUInt16(at: 0))
        
        // a server status request
        let expectedFlags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(try rawFlags.readUInt16(at: 0) == encodedFlags)
        
        // print("encodedFlags: \(encodedFlags) --> 0x\(String(format:"%02x", encodedFlags))")
    }
    
    @Test func testDNSFlags4() throws {
        // 0 0000 0 0 1 0 000 0011
        // let rawFlags: UInt16 = 0x103
        let rawFlags: Data = Data([0x01, 0x03])
        let parsedFlags = try DNSHeader.DNSFlags(from: try rawFlags.readUInt16(at: 0))
        
        // a server status request
        let expectedFlags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 3)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(try rawFlags.readUInt16(at: 0) == encodedFlags)
        
        // print("encodedFlags: \(encodedFlags) --> 0x\(String(format:"%02x", encodedFlags))")
    }
    
    @Test func testDNSFlags5() throws {
        // 1 0010 1 0 1 1 000 0000
        let rawFlags: UInt16 = 0x9580
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        // a server status request
        let expectedFlags = DNSHeader.DNSFlags(qr: 1, opcode: 2, aa: 1, tc: 0, rd: 1, ra: 1, rcode: 0)
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
        
        // print("encodedFlags: \(encodedFlags) --> 0x\(String(format:"%02x", encodedFlags))")
    }
    
    @Test func testDNSFlags6() throws {
        // 1 0010 1 1 0 1 000 0000
        let rawFlags: UInt16 = 0x9680
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        // a server status request
        let expectedFlags = DNSHeader.DNSFlags(qr: 1, opcode: 2, aa: 1, tc: 1, rd: 0, ra: 1, rcode: 0)
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
        
        // print("encodedFlags: \(encodedFlags) --> 0x\(String(format:"%02x", encodedFlags))")
    }
    
    @Test func testDNSFlags7() throws {
        // 0 0000 0 0 1 0 000 0000
        let rawFlags: UInt16 = 0x100
        let parsedFlags = try DNSHeader.DNSFlags(from: rawFlags)
        
        let expectedFlags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        #expect(parsedFlags == expectedFlags)
        
        // -------------
        
        let encodedFlags = expectedFlags.toRaw()
        
        #expect(rawFlags == encodedFlags)
    }
}


