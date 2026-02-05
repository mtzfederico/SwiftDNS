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
    // MARK: Test DNSRecordType initliazers and values
    
    @Test func DNSRecordTypeFromString() {
        #expect(DNSRecordType.allCases.count == 24)
        for type in DNSRecordType.allCases {
            let description = type.description
            #expect(DNSRecordType(description) == type)
            #expect(DNSRecordType(description.lowercased()) == type)
        }
    }
    
    @Test func DNSRecordTypeFromValue() {
        for type in DNSRecordType.allCases {
            #expect(DNSRecordType(type.rawValue) == type)
        }
        
        // Test an unknown value
        let type128 = DNSRecordType.unknown(128)
        #expect(type128.description == "TYPE128")
        #expect(DNSRecordType("TYPE128") == type128)
        #expect(DNSRecordType("type128") == type128)
    }
    
    // MARK: Test DNSClass initliazers and values
    
    @Test func DNSClassFromString() {
        #expect(DNSClass.allCases.count == 5)
        for type in DNSClass.allCases {
            let description = type.description
            #expect(DNSClass(description) == type)
            #expect(DNSClass(description.lowercased()) == type)
        }
    }
    
    @Test func DNSClassFromValue() {
        for type in DNSClass.allCases {
            #expect(DNSClass(type.rawValue) == type)
        }
        
        // Test an unknown value
        let type128 = DNSClass.unknown(128)
        #expect(type128.description == "CLASS128")
        #expect(DNSClass("CLASS128") == type128)
        #expect(DNSClass("class128") == type128)
    }
    
    // MARK: Test SVCParamKeys initliazers and values
    
    @Test func SVCParamKeysFromString() {
        #expect(SVCParamKeys.allCases.count == 11)
        
        for type in SVCParamKeys.allCases {
            let description = type.description
            #expect(SVCParamKeys(description) == type)
            #expect(SVCParamKeys(description.uppercased()) == type)
        }
    }
    
    @Test func SVCParamKeysFromValue() {
        for type in SVCParamKeys.allCases {
            #expect(SVCParamKeys(type.rawValue) == type)
        }
        
        // Test an unknown value
        let type128 = SVCParamKeys.unknown(128)
        #expect(type128.description == "key128")
        #expect(SVCParamKeys("key128") == type128)
        #expect(SVCParamKeys("KEY128") == type128)
    }
    
    /// Parse an A record
    @Test func A() throws {
        let data: Data = Data([
            0x03,
            0x6e, 0x73, 0x33,                   // ns3
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
        
        let expectedRR = ResourceRecord(name: "ns3.google.com.", ttl: 85839, Class: .internet, type: .A, value: "216.239.36.10")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "google.com.", ttl: 85839, Class: .internet, type: .NS, value: "ns1.google.com.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "www.infinitepartitions.com.", ttl: 7514, Class: .internet, type: .CNAME, value: "infinitepartitions.com.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
            0x00, 0x32,                                     // RDLength = 50 with compression
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
        
        let expectedRR = ResourceRecord(name: "as209245.net.", ttl: 1800, Class: .internet, type: .SOA, value: "josh.ns.cloudflare.com. dns.cloudflare.com. 2384946876 10000 2400 604800 1800")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
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
        
        let expectedRR = ResourceRecord(name: "34.48.210.189.in-addr.arpa.", ttl: 2884, Class: .internet, type: .PTR, value: "189-210-48-34.static.axtel.net.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.f.f.f.0.c.2.f.1.1.a.2.ip6.arpa.", ttl: 3600, Class: .internet, type: .PTR, value: "edge0.ams0.as209245.net.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func HINFO() throws {
        let data: Data = Data([
            0x08,
            0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x31, 0x30,                               // 01000110
            0x03,
            0x78, 0x79, 0x7a,                                                             // xyz
            0x00,                                                                         // name ends
            0x00, 0x0d,                                                                   // Type 13 = HINFO
            0x00, 0x01,                                                                   // Class IN
            0x00, 0x00, 0x21, 0x22,                                                       // TTL = 8482
            0x00, 0x1b,                                                                   // RDLength = 27
            0x0d,                                                                         // CPU Length = 13
            0x41, 0x4e, 0x59, 0x20, 0x6f, 0x62, 0x73, 0x6f, 0x6c, 0x65, 0x74, 0x65, 0x64, // ANY obsoleted
            0x0c,                                                                         // OS Length = 12
            0x53, 0x65, 0x65, 0x20, 0x52, 0x46, 0x43, 0x20, 0x38, 0x34, 0x38, 0x32,       // See RFC 8482
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "01000110.xyz.", ttl: 8482, Class: .internet, type: .HINFO, value: "ANY obsoleted, See RFC 8482")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "as209245.net.", ttl: 300, Class: .internet, type: .MX, value: "10 mx1.improvmx.com.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "as209245.net.", ttl: 26, Class: .internet, type: .AAAA, value: "2606:4700:3031:0:0:0:6815:5ad2")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
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
        
        let expectedRR = ResourceRecord(name: "_minecraft._tcp.fedemtz66.tech.", ttl: 300, Class: .internet, type: .SRV, value: "1 1 25564 dfw-1.fedemtz66.tech.")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    // MARK: DNSSEC
    
    // DS 43
    @Test func DS() throws {
         // dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A98631FAD1A292118 )
        
        let data = Data([
            0x05,
            0x64, 0x73, 0x6b, 0x65, 0x79,                           // dskey
            0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,               // example
            0x03,
            0x63, 0x6f, 0x6d,                                       // com
            0x00,
            
            0x00, 0x2b,                                             // 43 = DS
            0x00, 0x01,                                             // class IN
            0x00, 0x01, 0x51, 0x80,                                 // ttl = 86400
            0x00, 0x18,                                             // RD Length = 24
            
            0xec, 0x45,                                             // keyTag = 60485
            0x05,                                                   // algorithm = 5
            0x01,                                                   // digestType = 1
            
            0x2B, 0xB1, 0x83, 0xAF, 0x5F, 0x22, 0x58, 0x81, 0x79, 0xA5, 0x3B, 0x0A, 0x98, 0x63, 0x1F, 0xAD, 0x1A, 0x29, 0x21, 0x18,
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "dskey.example.com.", ttl: 86400, Class: .internet, type: .DS, value: "60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func SSHFP0() throws {
        // ams-1.fedemtz66.tech.    300    IN    SSHFP    1 1 9056700C6FFF1AC29F90C844ECE6CA586D897FBB
        
        let data = Data([
            0x05,
            0x61, 0x6d, 0x73, 0x2d, 0x31,                           // ams-1
            0x09,
            0x66, 0x65, 0x64, 0x65, 0x6d, 0x74, 0x7a, 0x36, 0x36,   // fedemtz66
            0x04,
            0x74, 0x65, 0x63, 0x68,                                 // tech
            0x00,
            
            0x00, 0x2c,                                             // 44 = SSHFP
            0x00, 0x01,                                             //
            0x00, 0x00, 0x01, 0x2c,                                 // ttl = 300
            0x00, 0x16,                                             // RD Length = 22
            0x01,                                                   // algorithm = 1
            0x01,                                                   // fp type = 1
            
            0x90, 0x56, 0x70, 0x0c, 0x6f, 0xff, 0x1a, 0xc2, 0x9f, 0x90, 0xc8, 0x44, 0xec, 0xe6, 0xca, 0x58, 0x6d, 0x89, 0x7f, 0xbb
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "ams-1.fedemtz66.tech.", ttl: 300, Class: .internet, type: .SSHFP, value: "1 1 9056700c6fff1ac29f90c844ece6ca586d897fbb")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func SSHFP1() throws {
        // ams-1.fedemtz66.tech.    300    IN    SSHFP    4 2 792E93389EB2A1C9B9044A25BE8357E0BE7C28A75BFA6A008AFCE720 DF4CBE25
        
        let data = Data([
            0x05,
            0x61, 0x6d, 0x73, 0x2d, 0x31,                           // ams-1
            0x09,
            0x66, 0x65, 0x64, 0x65, 0x6d, 0x74, 0x7a, 0x36, 0x36,   // fedemtz66
            0x04,
            0x74, 0x65, 0x63, 0x68,                                 // tech
            0x00,
            
            0x00, 0x2c,                                             // 44 = SSHFP
            0x00, 0x01,
            0x00, 0x00, 0x01, 0x2c,                                 // ttl = 300
            0x00, 0x22,                                             // RD Length = 34
            0x04,                                                   // algorithm = 4
            0x02,                                                   // fp type = 2
            
            0x79, 0x2e, 0x93, 0x38, 0x9e, 0xb2, 0xa1, 0xc9, 0xb9, 0x04, 0x4a, 0x25, 0xbe, 0x83, 0x57, 0xe0, 0xbe, 0x7c, 0x28, 0xa7,
            0x5b, 0xfa, 0x6a, 0x00, 0x8a, 0xfc, 0xe7, 0x20, 0xdf, 0x4c, 0xbe, 0x25
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "ams-1.fedemtz66.tech.", ttl: 300, Class: .internet, type: .SSHFP, value: "4 2 792e93389eb2a1c9b9044a25be8357e0be7c28a75bfa6a008afce720df4cbe25")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    // RRSIG 46
    @Test func RRSIG() throws {
        
        // https://www.rfc-editor.org/rfc/rfc4034.html#section-3.3
        /*
         host.example.com. 86400 IN RRSIG A 5 3 86400 20030322173103 (
         20030220173103 2642 example.com.
         oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr
         PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o
         B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t
         GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG
         J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )
         */
        
        #expect(false)
    }
    
    @Test func NSEC() throws {
        // Example from https://www.rfc-editor.org/rfc/rfc4034.html#section-4.3
        
        // alfa.example.com. 86400 IN NSEC host.example.com. ( A MX RRSIG NSEC TYPE1234 )
        
        let data = Data([
            0x04,
            0x61, 0x6c, 0x66, 0x61,                             // alfa
            0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,           // example
            0x03,
            0x63, 0x6f, 0x6d,                                   // com
            0x00,
            0x00, 0x2f,                                         // Type 47 = NSEC
            0x00, 0x01,                                         // class IN
            0x00, 0x01, 0x51, 0x80,                             // TTL = 86400
            0x00, 0x37,                                         // RDLength = 55
            0x04,
            0x68, 0x6f, 0x73, 0x74,                             // host
            0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,           // example
            0x03,
            0x63, 0x6f, 0x6d,                                   // com
            0x00,
            
            0x00,                                               // Block 0
            0x06,                                               // BitMap Length = 6
            0x40, 0x01, 0x00, 0x00, 0x00, 0x03,                 //
            
            0x04,
            0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "alfa.example.com.", ttl: 86400, Class: .internet, type: .NSEC, value: "host.example.com. A MX RRSIG NSEC TYPE1234")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    @Test func DNSKEY() throws {
        // mtzfederico.com.    3600    IN    DNSKEY    256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8 KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
        
        let data: Data = Data([
            0x0b,
            0x6d, 0x74, 0x7a, 0x66, 0x65, 0x64, 0x65, 0x72, 0x69, 0x63, 0x6f,
            0x03,
            0x63, 0x6f, 0x6d,
            0x00,
            0x00, 0x30,
            0x00, 0x01,
            0x00, 0x00, 0x0e, 0x10,
            0x00, 0x44,
            0x01, 0x00,
            0x03,
            0x0d,
            0xa0, 0x93, 0x11, 0x11, 0x2c, 0xf9, 0x13, 0x88, 0x18, 0xcd, 0x2f, 0xea,
            0xe9, 0x70, 0xeb, 0xbd, 0x4d, 0x6a, 0x30, 0xf6, 0x08, 0x8c, 0x25, 0xb3,
            0x25, 0xa3, 0x9a, 0xbb, 0xc5, 0xcd, 0x11, 0x97, 0xaa, 0x09, 0x82, 0x83,
            0xe5, 0xaa, 0xf4, 0x21, 0x17, 0x7c, 0x2a, 0xa5, 0xd7, 0x14, 0x99, 0x2a,
            0x99, 0x57, 0xd1, 0xbc, 0xc1, 0x8f, 0x98, 0xcd, 0x71, 0xf1, 0xf1, 0x80,
            0x6b, 0x65, 0xe1, 0x48,
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "mtzfederico.com.", ttl: 3600, Class: .internet, type: .DNSKEY, value: "256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
    
    // NSEC3 50
    @Test func NSEC3() throws {
        #expect(false)
    }
    
    // SVCB 64
    @Test func SVCB() throws {
        let data: Data = Data([
            0x03,
            0x5F, 0x37, 0x30,                                                   // _70
            0x07,
            0x5F, 0x67, 0x6F, 0x70, 0x68, 0x65, 0x72,                           // _gopher
            0x0a,
            0x63, 0x6F, 0x6C, 0x69, 0x6E, 0x63, 0x6F, 0x67, 0x6C, 0x65,         // colincogle
            0x04,
            0x6E, 0x61, 0x6D, 0x65,                                             // name
            0x00,
            0x00, 0x40,                                                         // type 64 = SVCB
            0x00, 0x01,                                                         // class in
            0x00, 0x00, 0xa7, 0x18,                                             // TTL = 42776
            0x00, 0x38,                                                         // RDLength = 56
            0x00, 0x04,                                                         // SvcPriority = 4
            0x02,                                                               // targetName begins
            0x65, 0x75,                                                         // eu
            0x0a,
            0x63, 0x6F, 0x6C, 0x69, 0x6E, 0x63, 0x6F, 0x67, 0x6C, 0x65,         // colincogle
            0x04,
            0x6E, 0x61, 0x6D, 0x65,                                             // name
            0x00,                                                               // targetName ends
            
            0x00, 0x03,                                                         // port
            0x00, 0x02,                                                         // SvcParamValue length = 2
            0x00, 0x46,                                                         // 70
            
            0x00, 0x04,                                                         // ipv4hint
            0x00, 0x04,                                                         // SvcParamValue length = 4
            0x33, 0x9f, 0xba, 0x55,                                             // 51.159.186.85
            
            0x00, 0x06,                                                         // ipv6hint
            0x00, 0x10,                                                         // SvcParamValue length = 16
            // 2001:0bc8:1200:fa28::1
            0x20, 0x01, 0x0b, 0xc8, 0x12, 0x00, 0xfa, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        print("parsedRR: \(parsedRR.description)")
        
        let expectedRR = ResourceRecord(name: "_70._gopher.colincogle.name.", ttl: 42776, Class: .internet, type: .SVCB, value: "4 eu.colincogle.name. port=70 ipv4hint=51.159.186.85 ipv6hint=2001:bc8:1200:fa28:0:0:0:1")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        print("rrOut: \(rrOut.hexEncodedString())")
        #expect(rrOut == data)
    }
    
    // HTTPS 65
    @Test func HTTPS() throws {
        let data: Data = Data([
            0x0a,
            0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72, 0x65,         // cloudflare
            0x03,
            0x63, 0x6f, 0x6d,                                                   // com
            0x00,
            0x00, 0x41,                                                         // type 65 = HTTPS
            0x00, 0x01,                                                         // class in
            0x00, 0x00, 0x00, 0x00,                                             // TTL = 0
            0x00, 0x3d,                                                         // RDLength = 61
            0x00, 0x01,                                                         // SvcPriority = 1
            0x00,                                                               // targetName
            
            0x00, 0x01,                                                         // alpn
            0x00, 0x06,                                                         // SvcParamValue length = 6
            0x02,                                                               // len = 2
            0x68, 0x33,                                                         // h3
            0x02,                                                               // len = 2
            0x68, 0x32,                                                         // h2
            
            0x00, 0x04,                                                         // ipv4hint
            0x00, 0x08,                                                         // SvcParamValue length = 8
            0x68, 0x10, 0x84, 0xe5,                                             // 104.16.132.229
            0x68, 0x10, 0x85, 0xe5,                                             // 104.16.133.229
            
            0x00, 0x06,                                                         // ipv6hint
            0x00, 0x20,                                                         // SvcParamValue length = 32
            // 2606:4700:0000:0000:0000:0000:6810:84e5
            0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x10, 0x84, 0xe5,
            // 2606:4700:0000:0000:0000:0000:6810:85e5
            0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x10, 0x85, 0xe5,
        ])
        
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        print("parsedRR: \(parsedRR.description)")
        
        let expectedRR = ResourceRecord(name: "cloudflare.com.", ttl: 0, Class: .internet, type: .HTTPS, value: "1 . alpn=h3,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700:0:0:0:0:6810:84e5,2606:4700:0:0:0:0:6810:85e5")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        print("rrOut: \(rrOut.hexEncodedString())")
        #expect(rrOut == data)
    }
    
    // Tests an unknown type with code 123
    @Test func unknown123() throws {
        // example.com.    3600    IN    TYPE123    256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8 KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==
        
        let data: Data = Data([
            0x07,
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,               // example
            0x03,
            0x63, 0x6f, 0x6d,                                       // com
            0x00,
            0x00, 0x7b,                                             // type 123
            0x00, 0x01,                                             // class in
            0x00, 0x00, 0x0e, 0x10,                                 // TTL = 3600
            0x00, 0x38,                                             // rdlength = 56
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
            0x21, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6E,
            0x20, 0x75, 0x6E, 0x6B, 0x6E, 0x6F, 0x77, 0x6E, 0x20, 0x52, 0x65, 0x73,
            0x6F, 0x75, 0x72, 0x63, 0x65, 0x20, 0x52, 0x65, 0x63, 0x6F, 0x72, 0x64,
            0x27, 0x73, 0x20, 0x52, 0x44, 0x41, 0x54, 0x41,
        ])
        
        var offset = 0
        let parsedRR = try ResourceRecord(data: data, offset: &offset)
        
        let expectedRR = ResourceRecord(name: "example.com.", ttl: 3600, Class: .internet, type: .unknown(123), value: "\\# 56 48656c6c6f2c20576f726c6421205468697320697320616e20756e6b6e6f776e205265736f75726365205265636f72642773205244415441")
        #expect(parsedRR == expectedRR)
        
        #expect(ResourceRecord(expectedRR.description) == expectedRR)
        
        var nameOffsets: [String: Int] = [:]
        let rrOut = try parsedRR.toData(messageLength: 0, nameOffsets: &nameOffsets)
        #expect(rrOut == data)
    }
}
