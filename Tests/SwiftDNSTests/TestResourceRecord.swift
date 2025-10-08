//
//  TestResourceRecord.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-07
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestResourceRecord {
    
    /// Parse an A record
    @Test func A() throws {
        let data: Data = Data([
            0x03,
            0x6e, 0x73, 0x33,
            0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0x03,
            0x63, 0x6f, 0x6d,                   // com
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "ns3.google.com", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.A, value: "216.239.36.10")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    /// Parse an NS record
    @Test func NS() throws {
        let data: Data = Data([
            0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0x03,
            0x63, 0x6f, 0x6d,                   // com
            0x00,
            
            0x00, 0x02,                         // TYPE 2 = NS
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x06,                         // rdlength = 6
            0x03,
            0x6e, 0x73, 0x31,                   // ns1
            0xc0, 0x00,                         // pointer to beginning
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "google.com", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.NS, value: "ns1.google.com")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func CNAME() throws {
        let data: Data = Data([
            0x03,
            0x77, 0x77, 0x77,                               // www
            0x12,
            0x69, 0x6e, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x65, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73,
            0x03,
            0x63, 0x6f, 0x6d,                               // com
            0x00,
            0x00, 0x05,                                     // TYPE 5 = CNAME
            0x00, 0x01,                                     // class IN
            0x00, 0x00, 0x1d, 0x5a,                         // TTL = 7514
            0x00, 0x02,                                     // RDLength = 20
            0xc0, 0x04                                      // pointer to position 4. right after www
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "www.infinitepartitions.com", ttl: 7514, Class: DNSClass.internet, type: DNSRecordType.CNAME, value: "infinitepartitions.com")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func SOA() throws {
        let data = Data([
            0x08,
            0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, // as209245
            0x03,
            0x6e, 0x65, 0x74,                               // net
            0x00,
            0x00, 0x06,                                     // TYPE 6 = SOA
            0x00, 0x01,                                     // class IN
            0x00, 0x00, 0x07, 0x08,                         // TTL = 1800
            0x00, 0x32,                                     // RDLength = 64 with no compression 50 with compression
            // MNAME
            0x04,
            0x6a, 0x6F, 0x73, 0x68,                         // josh
            0x02,
            0x6e, 0x73,                                     // ns
            0x0a,                                           // 0x20
            0x63, 0x6C, 0x6F, 0x75, 0x64, 0x66, 0x6C, 0x61, 0x72, 0x65, // cloudflare
            0x03,
            0x63, 0x6f, 0x6d,                               // com
            0x00,
            // RNAME
            0x03,
            0x64, 0x6e, 0x73,                               // dns
            0xc0, 0x20,                                     // pointer to cloudflare.com in MNAME
            // SERIAL
            0x8e, 0x27, 0x66, 0xbc,                         // 2384946876
            // REFRESH
            0x00, 0x00, 0x27, 0x10,                         // 10000
            // RETRY
            0x00, 0x00, 0x09, 0x60,                         // 2400
            // EXPIRE
            0x00, 0x09, 0x3A, 0x80,                         // 604800
            // MINIMUM
            0x00, 0x00, 0x07, 0x08,                         // 1800
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "as209245.net", ttl: 1800, Class: DNSClass.internet, type: DNSRecordType.SOA, value: "josh.ns.cloudflare.com dns.cloudflare.com 2384946876 10000 2400 604800 1800")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        print("SOA: \(rrOut.hexEncodedString())")
        #expect(rrOut == data)
    }
    
    @Test func PTR_IPv4() throws {
        let data = Data([
            0x02,
            0x33, 0x34,                                 // "34"
            0x02,
            0x34, 0x38,                                 // "48"
            0x03,
            0x32, 0x31, 0x30,                           // "210"
            0x03,
            0x31, 0x38, 0x39,                           // "189"
            0x07,
            0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72,   // "in-addr"
            0x04,
            0x61, 0x72, 0x70, 0x61,                     // "arpa"
            0x00,                                       // end of name
            
            0x00, 0x0c,                                 // TYPE 12 = PTR
            0x00, 0x01,                                 // class IN
            0x00, 0x00, 0x0b, 0x44,                     // TTL = 2884
            0x00, 0x20,                                 // RDLENGTH = 32
            
            0x0d,
            0x31, 0x38, 0x39, 0x2d, 0x32, 0x31, 0x30, 0x2d, 0x34, 0x38, 0x2d, 0x33, 0x34, // "189-210-48-34"
            0x06,
            0x73, 0x74, 0x61, 0x74, 0x69, 0x63,         // "static"
            0x05,
            0x61, 0x78, 0x74, 0x65, 0x6c,               // "axtel"
            0x03,
            0x6e, 0x65, 0x74,                           // "net"
            0x00                                        // end of name
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "34.48.210.189.in-addr.arpa", ttl: 2884, Class: DNSClass.internet, type: DNSRecordType.PTR, value: "189-210-48-34.static.axtel.net")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func PTR_IPv6() throws {
        let data = Data([
            0x01, 0x31, // 1
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x30, // 0
            0x01, 0x37, // 7
            0x01, 0x66, // f
            0x01, 0x66, // f
            0x01, 0x66, // f
            0x01, 0x30, // 0
            0x01, 0x63, // c
            0x01, 0x32, // 2
            0x01, 0x66, // f
            0x01, 0x31, // 1
            0x01, 0x31, // 1
            0x01, 0x61, // a
            0x01, 0x32, // 2
            0x03, 0x69, 0x70, 0x36, // ip6
            0x04, 0x61, 0x72, 0x70, 0x61, // arpa
            0x00,                                           // name ends
            0x00, 0x0c,                                     // Type 12 = PTR
            0x00, 0x01,                                     // Class IN
            0x00, 0x00, 0x0e, 0x10,                         // TTL = 3600
            0x00, 0x19,                                     // RDLength = 25
            0x05,
            0x65, 0x64, 0x67, 0x65, 0x30,                   // edge0
            0x04,
            0x61, 0x6d, 0x73, 0x30,                         // ams0
            0x08,
            0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, // as209245
            0x03,
            0x6e, 0x65, 0x74,                               // net
            0x00
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.f.f.f.0.c.2.f.1.1.a.2.ip6.arpa", ttl: 3600, Class: DNSClass.internet, type: DNSRecordType.PTR, value: "edge0.ams0.as209245.net")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func MX() throws {
        let data = Data([
            0x08,
            0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, // as209245
            0x03,
            0x6e, 0x65, 0x74,                               // net
            0x00,
            0x00, 0x0f,                                     // Type 15 = MX
            0x00, 0x01,                                     // class IN
            0x00, 0x00, 0x01, 0x2c,                         // TTL = 300
            0x00, 0x14,                                     // RDLength = 20
            0x00, 0x0a,                                     // Preference = 10
            0x03,
            0x6d, 0x78, 0x31,                               // mx1
            0x08,
            0x69, 0x6D, 0x70, 0x72, 0x6F, 0x76 ,0x6D, 0x78, // improvmx
            0x03,
            0x63, 0x6f, 0x6d,                               // com
            0x00
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "as209245.net", ttl: 300, Class: DNSClass.internet, type: DNSRecordType.MX, value: "10 mx1.improvmx.com")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func AAAA() throws {
        let data = Data([
            0x08,
            0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, // as209245
            0x03,
            0x6e, 0x65, 0x74,                               // net
            0x00,
            0x00, 0x1c,                                     // Type 28 = AAAA
            0x00, 0x01,                                     // in
            0x00, 0x00, 0x00, 0x1a,                         // TTL = 26
            0x00, 0x10,                                     // RDLength
            
            // 2606:4700:3031:0000:0000:0000:6815:5ad2
            0x26, 0x06,
            0x47, 0x00,
            0x30, 0x31,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x68, 0x15,
            0x5a, 0xd2
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "as209245.net", ttl: 26, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2606:4700:3031:0:0:0:6815:5ad2")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func SRV() throws {
        let data = Data([
            0x0a,
            0x5f, 0x6d, 0x69, 0x6e, 0x65, 0x63, 0x72, 0x61, 0x66, 0x74, // _minecraft
            0x04,
            0x5f, 0x74, 0x63, 0x70,                                     // _tcp
            0x09,
            0x66, 0x65, 0x64, 0x65, 0x6D, 0x74, 0x7A, 0x36, 0x36,       // fedemtz66
            0x04,
            0x74, 0x65, 0x63, 0x68,                                     // tech
            0x00,
            0x00, 0x21,                                                 // Type 33 = SRV
            0x00, 0x01,                                                 // class IN
            0x00, 0x00, 0x01, 0x2c,                                     // TTL = 300
            0x00, 0x0e,                                                 // RDLength = 14
            
            0x00, 0x01,                                                 // Priority = 1
            0x00, 0x01,                                                 // Weight = 1
            0x63, 0xdc,                                                 // Port = 25564
            
            // Target
            0x05,
            0x64, 0x66, 0x77, 0x2d, 0x31,                               // dfw-1
            0xc0, 0x10,                                                 // pointer to fedemtz66.tech
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "_minecraft._tcp.fedemtz66.tech", ttl: 300, Class: DNSClass.internet, type: DNSRecordType.SRV, value: "1 1 25564 dfw-1.fedemtz66.tech")
        #expect(parsedRR == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    // DNSSEC 
}
