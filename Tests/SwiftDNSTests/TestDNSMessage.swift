//
//  TestDNSMessage.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestDNSMessage {
    @Test func query_A() throws {
        
        // 76 43
        // 01 00
        // 00 01
        // 00 00
        // 00 00
        // 00 00
        // 08 61 73 32 30 39 32 34 35
        // 03 6e 65 74 00
        // 00 01
        // 00 01
        
        let data: Data = Data([
            0x76, 0x43,  // Transaction ID
            0x01, 0x00,  // Flags (QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=000, RCODE=0) --> 0 0000 0 0 1 0 000 0000
            0x00, 0x01,  // QDCOUNT (1 question)
            0x00, 0x00,  // ANCOUNT (0 answers)
            0x00, 0x00,  // NSCOUNT (0 authority records)
            0x00, 0x00,  // ARCOUNT (0 additional records)
            
            // QNAME (example.com)
            0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34,  // "as209245"
            0x35, 0x03, 0x6e, 0x65,  // "net"
            0x74, 0x00, // End of QNAME
            
            0x00, 0x01,  // QTYPE (A record)
            0x00, 0x01   // QCLASS (IN class)
        ])
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x7643, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        let expectedQuestion = QuestionSection(host: "as209245.net.", type: .A, CLASS: .internet)
        let fullData = expectedHeader.toData() + (try expectedQuestion.toData())
        
        #expect(fullData == data)
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        #expect(parsedAnswer.header == expectedHeader)
        #expect(parsedAnswer.header.flags == expectedFlags)
        
        #expect(parsedAnswer.header.QDCOUNT == 1)
        #expect(parsedAnswer.header.ANCOUNT == 0)
        #expect(parsedAnswer.header.NSCOUNT == 0)
        #expect(parsedAnswer.header.ARCOUNT == 0)
        
        #expect(parsedAnswer.Question.first! == expectedQuestion)
    }
    
    @Test func query_AAAA() throws {
        let data = Data([
            0xa1, 0x7c,  // [0-1]   ID = a17c
            0x01, 0x00,  // [2-3]   Flags
            0x00, 0x01,  // [4-5]   QDCOUNT = 1
            0x00, 0x00,  // [6-7]   ANCOUNT = 0
            0x00, 0x00,  // [8-9]   NSCOUNT = 0
            0x00, 0x00,  // [10-11] ARCOUNT = 0
            0x0a, 0x62, 0x61, 0x6e, 0x64, 0x61, 0x61, 0x6e, 0x63, 0x68, 0x61, // [12-22] Label "bandaancha"
            0x02, 0x65, 0x75,             // [23-25] Label "eu"
            0x00,                         // [26]    End of QNAME
            0x00, 0x1c,                   // [27-28] QTYPE (AAAA)
            0x00, 0x01                    // [29-30] QCLASS (IN)
        ])
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0xa17c, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        let expectedQuestion = QuestionSection(host: "bandaancha.eu.", type: .AAAA, CLASS: .internet)
        let fullData = expectedHeader.toData() + (try expectedQuestion.toData())
        
        #expect(fullData == data)
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        #expect(parsedAnswer.header == expectedHeader)
        #expect(parsedAnswer.header.flags == expectedFlags)
        
        #expect(parsedAnswer.header.QDCOUNT == 1)
        #expect(parsedAnswer.header.ANCOUNT == 0)
        #expect(parsedAnswer.header.NSCOUNT == 0)
        #expect(parsedAnswer.header.ARCOUNT == 0)
        
        #expect(parsedAnswer.Question.first! == expectedQuestion)
        
        // print("expectedHeader: \(expectedHeader.toData().hexEncodedString())\nexpectedQuestion: \(expectedQuestion.toData().hexEncodedString())\nfullData: \(fullData.hexEncodedString())\ndata: \(data.hexEncodedString())")
    }
    
    @Test func query_CH_TXT() throws {
        
        let data = Data([
            0x5e, 0xf4,   // ID
            0x01, 0x00,   // Flags
            0x00, 0x01,   // QDCOUNT
            0x00, 0x00,   // ANCOUNT
            0x00, 0x00,   // NSCOUNT
            0x00, 0x00,   // ARCOUNT
            0x02, 0x69, 0x64, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, // "id" and "server"
            0x00,         // End of QNAME
            0x00, 0x10,   // QTYPE (TXT)
            0x00, 0x03    // QCLASS (CH)
        ])
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x5ef4, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        let expectedQuestion = QuestionSection(host: "id.server.", type: .TXT, CLASS: .chaos)
        let fullData = expectedHeader.toData() + (try expectedQuestion.toData())
        
        #expect(fullData == data)
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        #expect(parsedAnswer.header == expectedHeader)
        #expect(parsedAnswer.header.flags == expectedFlags)
        
        #expect(parsedAnswer.header.QDCOUNT == 1)
        #expect(parsedAnswer.header.ANCOUNT == 0)
        #expect(parsedAnswer.header.NSCOUNT == 0)
        #expect(parsedAnswer.header.ARCOUNT == 0)
        
        #expect(parsedAnswer.Question.first! == expectedQuestion)
    }
    
    // MARK: Responses
    
    /// Parse a DNS NS query response
    @Test func ns_response() throws {
        // e1a88180000100040000000806676f6f676c6503636f6d0000020001c00c0002000100014f4f0006036e7331c00cc00c0002000100014f4f0006036e7333c00cc00c0002000100014f4f0006036e7334c00cc00c0002000100014f4f0006036e7332c00cc03a0001000100014f4f0004d8ef240ac03a001c000100014f4f00102001486048020036000000000000000ac04c0001000100014f4f0004d8ef260ac04c001c000100014f4f00102001486048020038000000000000000ac05e0001000100014f4f0004d8ef220ac05e001c000100014f4f00102001486048020034000000000000000ac0280001000100014f4f0004d8ef200ac028001c000100014f4f00102001486048020032000000000000000a
       
        let data: Data = Data([
            0xe1, 0xa8, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x02, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01,
            0x4f, 0x4f, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x0c, 0xc0, 0x0c,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x06, 0x03, 0x6e,
            0x73, 0x33, 0xc0, 0x0c, 0xc0, 0x0c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01,
            0x4f, 0x4f, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x34, 0xc0, 0x0c, 0xc0, 0x0c,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x06, 0x03, 0x6e,
            0x73, 0x32, 0xc0, 0x0c, 0xc0, 0x3a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x4f, 0x4f, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0, 0x3a, 0x00, 0x1c,
            0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60,
            0x48, 0x02, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0xc0, 0x4c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x04,
            0xd8, 0xef, 0x26, 0x0a, 0xc0, 0x4c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01,
            0x4f, 0x4f, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x38,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xc0, 0x5e, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a,
            0xc0, 0x5e, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x10,
            0x20, 0x01, 0x48, 0x60, 0x48, 0x02, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0a, 0xc0, 0x28, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            0x4f, 0x4f, 0x00, 0x04, 0xd8, 0xef, 0x20, 0x0a, 0xc0, 0x28, 0x00, 0x1c,
            0x00, 0x01, 0x00, 0x01, 0x4f, 0x4f, 0x00, 0x10, 0x20, 0x01, 0x48, 0x60,
            0x48, 0x02, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        
        let parsedOut = try DNSMessage(data: dataOut)
        #warning("check this") // if the test fails, add a comment explaining why and leave it commented out
        // #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\nReference:  \(data.hexEncodedString())")
        
        #expect(parsedAnswer == parsedOut)
        // print("----------------------------\nOutput:\n\(parsedOut.description)\n\nReference:\n\(parsedAnswer.description)\n----------------------------")
        #expect(parsedAnswer.header.id == 0xe1a8)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .NS, CLASS: .internet)
        
        #expect(parsedAnswer.header.QDCOUNT == 1)
        #expect(parsedAnswer.header.ANCOUNT == 4)
        #expect(parsedAnswer.header.NSCOUNT == 0)
        #expect(parsedAnswer.header.ARCOUNT == 8)
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        
        let expectedAnswer1 = ResourceRecord(name: "google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.NS, value: "ns1.google.com.")
        let expectedAnswer2 = ResourceRecord(name: "google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.NS, value: "ns3.google.com.")
        let expectedAnswer3 = ResourceRecord(name: "google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.NS, value: "ns4.google.com.")
        let expectedAnswer4 = ResourceRecord(name: "google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.NS, value: "ns2.google.com.")
        
        
        #expect(parsedAnswer.Answer[0] == expectedAnswer1)
        #expect(parsedAnswer.Answer[1] == expectedAnswer2)
        #expect(parsedAnswer.Answer[2] == expectedAnswer3)
        #expect(parsedAnswer.Answer[3] == expectedAnswer4)
        
        let expectedAR0 = ResourceRecord(name: "ns3.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.A, value: "216.239.36.10")
        let expectedAR1 = ResourceRecord(name: "ns3.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:4860:4802:36:0:0:0:a")
        
        let expectedAR2 = ResourceRecord(name: "ns4.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.A, value: "216.239.38.10")
        let expectedAR3 = ResourceRecord(name: "ns4.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:4860:4802:38:0:0:0:a")
        
        let expectedAR4 = ResourceRecord(name: "ns2.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.A, value: "216.239.34.10")
        let expectedAR5 = ResourceRecord(name: "ns2.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:4860:4802:34:0:0:0:a")
        
        let expectedAR6 = ResourceRecord(name: "ns1.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.A, value: "216.239.32.10")
        let expectedAR7 = ResourceRecord(name: "ns1.google.com.", ttl: 85839, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:4860:4802:32:0:0:0:a")
        
        #expect(parsedAnswer.Additional[0] == expectedAR0)
        #expect(parsedAnswer.Additional[1] == expectedAR1)
        
        #expect(parsedAnswer.Additional[2] == expectedAR2)
        #expect(parsedAnswer.Additional[3] == expectedAR3)
        
        #expect(parsedAnswer.Additional[4] == expectedAR4)
        #expect(parsedAnswer.Additional[5] == expectedAR5)
    
        #expect(parsedAnswer.Additional[6] == expectedAR6)
        #expect(parsedAnswer.Additional[7] == expectedAR7)
    }
    
    @Test func multi_aaaa_response() throws {
        // 42d281800001000200000000086173323039323435036e657400001c0001c00c001c00010000001a001026064700303100000000000068155ad2c00c001c00010000001a0010260647003037000000000000ac43a168
        
        let data = Data([
            0x42, 0xd2, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, 0x03, 0x6e, 0x65,
            0x74, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x1a, 0x00, 0x10, 0x26, 0x06, 0x47, 0x00, 0x30, 0x31,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x15, 0x5a, 0xd2, 0xc0, 0x0c,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x10, 0x26, 0x06,
            0x47, 0x00, 0x30, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x43,
            0xa1, 0x68
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x42d2, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 2, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 2)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "as209245.net.", type: .AAAA, CLASS: .internet)
        
        let expectedAnswer0 = ResourceRecord(name: "as209245.net.", ttl: 26, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2606:4700:3031:0:0:0:6815:5ad2")
        let expectedAnswer1 = ResourceRecord(name: "as209245.net.", ttl: 26, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2606:4700:3037:0:0:0:ac43:a168")
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(parsedAnswer.Answer[0] == expectedAnswer0)
        #expect(parsedAnswer.Answer[1] == expectedAnswer1)
    }
    
    @Test func ptr_ipv4() throws {
        let data = Data([
            0x8b, 0x3a,             // ID
            0x81, 0x80,             // Flags (standard response, no error)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            
            // QNAME: 334.48.210.189.in-addr.arpa
            0x02, 0x33, 0x34,       // label: "34"
            0x02, 0x34, 0x38,       // label: "48"
            0x03, 0x32, 0x31, 0x30, // label: "210"
            0x03, 0x31, 0x38, 0x39, // label: "189"
            0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, // label: "in-addr"
            0x04, 0x61, 0x72, 0x70, 0x61, // label: "arpa"
            0x00,                   // end of QNAME
            
            0x00, 0x0c,             // QTYPE = PTR
            0x00, 0x01,             // QCLASS = IN
            
            // Answer section
            0xc0, 0x0c,             // NAME (pointer to offset 12)
            0x00, 0x0c,             // TYPE = PTR
            0x00, 0x01,             // CLASS = IN
            0x00, 0x00, 0x0b, 0x44, // TTL = 2884
            0x00, 0x20,             // RDLENGTH = 32
            
            // RDATA: 189-210-48-34.static.axtel.net
            0x0d, 0x31, 0x38, 0x39, 0x2d, 0x32, 0x31, 0x30, 0x2d, 0x34, 0x38, 0x2d, 0x33, 0x34, // "189-210-48-34"
            0x06, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63,       // "static"
            0x05, 0x61, 0x78, 0x74, 0x65, 0x6c,             // "axtel"
            0x03, 0x6e, 0x65, 0x74,                         // "net"
            0x00                                            // end of name
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x8b3a, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "34.48.210.189.in-addr.arpa.", type: .PTR, CLASS: .internet)
        
        let expectedAnswer = ResourceRecord(name: "34.48.210.189.in-addr.arpa.", ttl: 2884, Class: DNSClass.internet, type: DNSRecordType.PTR, value: "189-210-48-34.static.axtel.net.")
        
        guard let firstAnswer = parsedAnswer.Answer.first else {
            Issue.record("First answer is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstAnswer == expectedAnswer)
        #expect(firstQuestion == expectedQuestion)
    }
    
    @Test func ptr_ipv6() throws {
        // 7d5c818000010001000000000131013001300130013001300130013001300130013001300130013001300130013001300130013001370166016601660130016301320166013101310161013203697036046172706100000c0001c00c000c000100000e10001905656467653004616d7330086173323039323435036e657400
        
        let data = Data([
            0x7d, 0x5c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
            0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
            0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
            0x01, 0x30, 0x01, 0x30, 0x01, 0x37, 0x01, 0x66, 0x01, 0x66, 0x01, 0x66,
            0x01, 0x30, 0x01, 0x63, 0x01, 0x32, 0x01, 0x66, 0x01, 0x31, 0x01, 0x31,
            0x01, 0x61, 0x01, 0x32, 0x03, 0x69, 0x70, 0x36, 0x04, 0x61, 0x72, 0x70,
            0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01,
            0x00, 0x00, 0x0e, 0x10, 0x00, 0x19, 0x05, 0x65, 0x64, 0x67, 0x65, 0x30,
            0x04, 0x61, 0x6d, 0x73, 0x30, 0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32,
            0x34, 0x35, 0x03, 0x6e, 0x65, 0x74, 0x00
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x7d5c, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.f.f.f.0.c.2.f.1.1.a.2.ip6.arpa.", type: .PTR, CLASS: .internet)
        
        // as209245.net.        1800    IN    SOA    josh.ns.cloudflare.com. dns.cloudflare.com. 2379358730 10000 2400 604800 1800
        let expectedAnswer = ResourceRecord(name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.f.f.f.0.c.2.f.1.1.a.2.ip6.arpa.", ttl: 3600, Class: DNSClass.internet, type: DNSRecordType.PTR, value: "edge0.ams0.as209245.net.")
        
        guard let firstAnswer = parsedAnswer.Answer.first else {
            Issue.record("First answer is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstAnswer == expectedAnswer)
        #expect(firstQuestion == expectedQuestion)
    }
    
    @Test func svcb() throws {
        let data: Data = Data([
            0x46, 0x3c, 0x81, 0xa0, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
            
            0x03,
            0x5f, 0x37, 0x30,                                                       // _70
            0x07,
            0x5f, 0x67, 0x6f, 0x70, 0x68, 0x65, 0x72,                               // _gopher
            0x0a,
            0x63, 0x6f, 0x6c, 0x69, 0x6e, 0x63, 0x6f, 0x67, 0x6c, 0x65,             // colincogle
            0x04,
            0x6e, 0x61, 0x6d, 0x65,                                                 // name
            0x00,
            0x00, 0x40,                                                             // type 64 = SVCB
            0x00, 0x01,                                                             // class IN
            
            0xc0, 0x0c,                                                             // pointer to QNAME
            0x00, 0x40,                                                             // type 64 = SVCB
            0x00, 0x01,                                                             // class IN
            0x00, 0x00, 0xa8, 0xc0,                                                 // TTL = 43200
            0x00, 0x48,                                                             // RDLength = 72
            0x00, 0x01,                                                             // SVCB Priority = 1
            0x38,                                                                   // targetName begins. Length = 56
            0x63, 0x6f, 0x6c, 0x69, 0x6e, 0x63, 0x78, 0x76, 0x7a, 0x34, 0x34, 0x74, // colincxvz44t
            0x6f, 0x6a, 0x6a, 0x64, 0x7a, 0x62, 0x70, 0x65, 0x73, 0x65, 0x62, 0x6d, // ojjdzbpesebm
            0x6c, 0x35, 0x70, 0x6e, 0x79, 0x7a, 0x6c, 0x32, 0x67, 0x32, 0x71, 0x63, // l5pnyzl2g2qc
            0x79, 0x37, 0x69, 0x78, 0x68, 0x6d, 0x67, 0x68, 0x68, 0x6b, 0x66, 0x71, // y7ixhmghhkfq
            0x6f, 0x36, 0x34, 0x7a, 0x6d, 0x64, 0x79, 0x64,                         // o64zmdyd
            0x05,
            0x6f, 0x6e, 0x69, 0x6f, 0x6e,                                           // onion
            0x00,                                                                   // targetName ends
            
            0x00, 0x03,                                                             // port
            0x00, 0x02,                                                             // SvcParamValue length = 2
            0x00, 0x46,                                                             // 70
            
            0xc0, 0x0c,                                                             // pointer to QNAME
            0x00, 0x40,                                                             // type 64 = SVCB
            0x00, 0x01,                                                             // class IN
            0x00, 0x00, 0xa8, 0xc0,                                                 // TTL = 43200
            0x00, 0x3c,                                                             // RDLength = 60
            0x00, 0x02,                                                             // SVCB Priority = 2
            0x06,                                                                   // targetName begins. Length = 6
            0x75, 0x73, 0x65, 0x61, 0x73, 0x74,                                     // useast
            0x0a,
            0x63, 0x6f, 0x6c, 0x69, 0x6e, 0x63, 0x6f, 0x67, 0x6c, 0x65,             // colincogle
            0x04,
            0x6e, 0x61, 0x6d, 0x65,                                                 // name
            0x00,                                                                   // targetName ends
            
            0x00, 0x03,                                                             // port
            0x00, 0x02,                                                             // SvcParamValue length = 2
            0x00, 0x46,                                                             // 70
            
            0x00, 0x04,                                                             // ipv4hint
            0x00, 0x04,                                                             // SvcParamValue length = 4
            0x2d, 0x4f, 0xaa, 0xe1,                                                 // 45.79.170.225
            
            0x00, 0x06,                                                             // ipv6hint
            0x00, 0x10,                                                             // SvcParamValue length = 16
            // 2600:3c03:e000:0938:0000:0000:0000:0000
            0x26, 0x00, 0x3c, 0x03, 0xe0, 0x00, 0x09, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            
            0xc0, 0x0c,                                                             // pointer to QNAME
            0x00, 0x40,                                                             // type 64 = SVCB
            0x00, 0x01,                                                             // class IN
            0x00, 0x00, 0xa8, 0xc0,                                                 // TTL = 43200
            0x00, 0x38,                                                             // RDLength = 56
            0x00, 0x04,                                                             // SVCB Priority = 4
            0x02,                                                                   // targetName begins. Length = 2
            0x65, 0x75,                                                             // eu
            0x0a,
            0x63, 0x6f, 0x6c, 0x69, 0x6e, 0x63, 0x6f, 0x67, 0x6c, 0x65,             // colincogle
            0x04,
            0x6e, 0x61, 0x6d, 0x65,                                                 // name
            0x00,                                                                   // targetName ends
            
            0x00, 0x03,                                                             // port
            0x00, 0x02,                                                             // SvcParamValue length = 2
            0x00, 0x46,                                                             // 70
            
            0x00, 0x04,                                                             // ipv4hint
            0x00, 0x04,                                                             // SvcParamValue length = 4
            0x33, 0x9f, 0xba, 0x55,
            
            0x00, 0x06,                                                             // ipv6hints
            0x00, 0x10,                                                             // SvcParamValue length = 16
            // 2001:0bc8:1200:fa28:0000:0000:0000:0001
            0x20, 0x01, 0x0b, 0xc8, 0x12, 0x00, 0xfa, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            
            0x00,
            0x00, 0x29,                                                             // type 41 = OPT
            0x04, 0xd0,                                                             // requestor's UDP payload size = 1232
            0x00, 0x00, 0x00, 0x00,                                                 // extended RCODE and flags
            0x00, 0x00,                                                             // RDLength = 0
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: .NoError)
        let expectedHeader = DNSHeader(id: 0x463c, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 3, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 3)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        #expect(parsedAnswer.EDNSData != nil)
        
        let expectedQuestion = QuestionSection(host: "_70._gopher.colincogle.name.", type: .SVCB, CLASS: .internet)
        
        let expectedAnswer0 = ResourceRecord(name: "_70._gopher.colincogle.name.", ttl: 43200, Class: .internet, type: .SVCB, value: "1 colincxvz44tojjdzbpesebml5pnyzl2g2qcy7ixhmghhkfqo64zmdyd.onion. port=70")
        let expectedAnswer1 = ResourceRecord(name: "_70._gopher.colincogle.name.", ttl: 43200, Class: .internet, type: .SVCB, value: "2 useast.colincogle.name. port=70 ipv4hint=45.79.170.225 ipv6hint=2600:3c03:e000:938:0:0:0:0")
        let expectedAnswer2 = ResourceRecord(name: "_70._gopher.colincogle.name.", ttl: 43200, Class: .internet, type: .SVCB, value: "4 eu.colincogle.name. port=70 ipv4hint=51.159.186.85 ipv6hint=2001:bc8:1200:fa28:0:0:0:1")
        
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [])
        
        #expect(parsedAnswer.Question[0] == expectedQuestion)
        #expect(parsedAnswer.Answer[0] == expectedAnswer0)
        #expect(parsedAnswer.Answer[1] == expectedAnswer1)
        #expect(parsedAnswer.Answer[2] == expectedAnswer2)
        #expect(parsedAnswer.EDNSData! == expectedEDNS)
    }
    
    /// Tests the response of an A query that returns a CNAME
    @Test func a_cname0() throws {
        // 86fd8180000100040000000003777777056170706c6503636f6d0000010001c00c000500010000012c001a0d7777772d6170706c652d636f6d0176076161706c696d67c016c02b000500010000012c001b03777777056170706c6503636f6d07656467656b6579036e657400c051000500010000012c00190565363835380564736365390a616b616d616965646765c067c0780001000100000014000468518d2c

        let data: Data = Data([
            0x86, 0xfd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x77, 0x77, 0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00,
            0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x1a, 0x0d, 0x77, 0x77, 0x77, 0x2d,
            0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x63, 0x6f, 0x6d, 0x01, 0x76, 0x07,
            0x61, 0x61, 0x70, 0x6c, 0x69, 0x6d, 0x67, 0xc0, 0x16, 0xc0, 0x2b, 0x00,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x1b, 0x03, 0x77, 0x77,
            0x77, 0x05, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x07,
            0x65, 0x64, 0x67, 0x65, 0x6b, 0x65, 0x79, 0x03, 0x6e, 0x65, 0x74, 0x00,
            0xc0, 0x51, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x19,
            0x05, 0x65, 0x36, 0x38, 0x35, 0x38, 0x05, 0x64, 0x73, 0x63, 0x65, 0x39,
            0x0a, 0x61, 0x6b, 0x61, 0x6d, 0x61, 0x69, 0x65, 0x64, 0x67, 0x65, 0xc0,
            0x67, 0xc0, 0x78, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x04, 0x68, 0x51, 0x8d, 0x2c,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // print(parsedAnswer.description)
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x86fd, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 4, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 4)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "www.apple.com.", type: .A, CLASS: .internet)
        
        /*
         www.apple.com.        300    IN    CNAME    www-apple-com.v.aaplimg.com.
         www-apple-com.v.aaplimg.com. 300 IN    CNAME    www.apple.com.edgekey.net.
         www.apple.com.edgekey.net. 300    IN    CNAME    e6858.dsce9.akamaiedge.net.
         e6858.dsce9.akamaiedge.net. 20    IN    A    104.81.141.44
         */
        let expectedAnswer0 = ResourceRecord(name: "www.apple.com.", ttl: 300, Class: .internet, type: .CNAME, value: "www-apple-com.v.aaplimg.com.")
        let expectedAnswer1 = ResourceRecord(name: "www-apple-com.v.aaplimg.com.", ttl: 300, Class: .internet, type: .CNAME, value: "www.apple.com.edgekey.net.")
        let expectedAnswer2 = ResourceRecord(name: "www.apple.com.edgekey.net.", ttl: 300, Class: .internet, type: .CNAME, value: "e6858.dsce9.akamaiedge.net.")
        let expectedAnswer3 = ResourceRecord(name: "e6858.dsce9.akamaiedge.net.", ttl: 20, Class: .internet, type: DNSRecordType.A, value: "104.81.141.44")
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(parsedAnswer.Answer[0] == expectedAnswer0)
        #expect(parsedAnswer.Answer[1] == expectedAnswer1)
        #expect(parsedAnswer.Answer[2] == expectedAnswer2)
        #expect(parsedAnswer.Answer[3] == expectedAnswer3)
    }
    
    /// Tests the response of an A query that returns a CNAME with compression
    @Test func a_cname1() throws {
        // e888818000010002000000000377777712696e66696e697465706172746974696f6e7303636f6d0000010001c00c0005000100001d5a0002c010c0100001000100001d5a00044adcdb1d

        let data: Data = Data([
            0xe8, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x77, 0x77, 0x77, 0x12, 0x69, 0x6e, 0x66, 0x69, 0x6e, 0x69, 0x74,
            0x65, 0x70, 0x61, 0x72, 0x74, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
            0x00, 0x01, 0x00, 0x00, 0x1d, 0x5a, 0x00, 0x02, 0xc0, 0x10, 0xc0, 0x10,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x1d, 0x5a, 0x00, 0x04, 0x4a, 0xdc,
            0xdb, 0x1d,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // print(parsedAnswer.description)
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0xe888, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 2, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 2)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "www.infinitepartitions.com.", type: .A, CLASS: .internet)
        
        /*
         www.infinitepartitions.com. 7514 IN    CNAME    infinitepartitions.com.
         infinitepartitions.com.    7514    IN    A    74.220.219.29
         */
        let expectedAnswer0 = ResourceRecord(name: "www.infinitepartitions.com.", ttl: 7514, Class: .internet, type: .CNAME, value: "infinitepartitions.com.")
        let expectedAnswer1 = ResourceRecord(name: "infinitepartitions.com.", ttl: 7514, Class: .internet, type: .A, value: "74.220.219.29")
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(parsedAnswer.Answer[0] == expectedAnswer0)
        #expect(parsedAnswer.Answer[1] == expectedAnswer1)
    }
    
    @Test func nxDomainResponse() throws {
        let data: Data = Data([
            0x3e, 0xa9, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x08, 0x6e, 0x78, 0x64,
            0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x08, 0x61, 0x73,
            0x32, 0x30, 0x39, 0x32, 0x34, 0x35, 0x03, 0x6e,
            0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
            0x15, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x07,
            0x08, 0x00, 0x32, 0x04, 0x6a, 0x6f, 0x73, 0x68,
            0x02, 0x6e, 0x73, 0x0a, 0x63, 0x6c, 0x6f, 0x75,
            0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x03, 0x64, 0x6e, 0x73, 0xc0,
            0x3b, 0x8d, 0xd2, 0x22, 0x0a, 0x00, 0x00, 0x27,
            0x10, 0x00, 0x00, 0x09, 0x60, 0x00, 0x09, 0x3a,
            0x80, 0x00, 0x00, 0x07, 0x08
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        
        // NOTE: Test fails because cloudflare compressed less the SOA record
        #warning("try getting this data again and see if it is the same")
        // #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x3ea9, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 1, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 1)
        #expect(parsedAnswer.Additional.count == 0)
        
        
        let expectedQuestion = QuestionSection(host: "nxdomain.as209245.net.", type: .A, CLASS: .internet)
        
        // as209245.net.        1800    IN    SOA    josh.ns.cloudflare.com. dns.cloudflare.com. 2379358730 10000 2400 604800 1800
        let expectedAnswer = ResourceRecord(name: "as209245.net.", ttl: 1800, Class: DNSClass.internet, type: DNSRecordType.SOA, value: "josh.ns.cloudflare.com. dns.cloudflare.com. 2379358730 10000 2400 604800 1800")
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        guard let firstAuthority = parsedAnswer.Authority.first else {
            Issue.record("First authority is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(firstAuthority == expectedAnswer)
    }
    
    @Test func rootZone() throws {
        // 28d381800001000d0000000000000200010000020001000011c1001401650c726f6f742d73657276657273036e6574000000020001000011c100040162c01e0000020001000011c100040164c01e0000020001000011c100040166c01e0000020001000011c100040167c01e0000020001000011c100040163c01e0000020001000011c100040161c01e0000020001000011c10004016dc01e0000020001000011c10004016cc01e0000020001000011c10004016ac01e0000020001000011c10004016bc01e0000020001000011c100040168c01e0000020001000011c100040169c01e
        
        let data: Data = Data([
            0x28, 0xd3, 0x81, 0x80, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
            0x11, 0xc1, 0x00, 0x14, 0x01, 0x65, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d,
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01,
            0x62, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1,
            0x00, 0x04, 0x01, 0x64, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x66, 0xc0, 0x1e, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x67, 0xc0, 0x1e,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01,
            0x63, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1,
            0x00, 0x04, 0x01, 0x61, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x6d, 0xc0, 0x1e, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x6c, 0xc0, 0x1e,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01,
            0x6a, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x11, 0xc1,
            0x00, 0x04, 0x01, 0x6b, 0xc0, 0x1e, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
            0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x68, 0xc0, 0x1e, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x00, 0x11, 0xc1, 0x00, 0x04, 0x01, 0x69, 0xc0, 0x1e,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // print(parsedAnswer.description)
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("----------------------------\nOutput:\n\(parsedOut.description)\n\nReference:\n\(parsedAnswer.description)\n----------------------------")
        
        /*
         ;; header: ID: 0x28d3, DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, z: 0, rcode: SwiftDNS.DNSResponseCode.NoError), QDCOUNT: 1, ANCOUNT: 13, NSCOUNT: 0, ARCOUNT: 0
         ;; Questions:
          IN NS
         ;; Answer:
          4545 IN NS e.root-servers.net
          4545 IN NS b.root-servers.net
          4545 IN NS d.root-servers.net
          4545 IN NS f.root-servers.net
          4545 IN NS g.root-servers.net
          4545 IN NS c.root-servers.net
          4545 IN NS a.root-servers.net
          4545 IN NS m.root-servers.net
          4545 IN NS l.root-servers.net
          4545 IN NS j.root-servers.net
          4545 IN NS k.root-servers.net
          4545 IN NS h.root-servers.net
          4545 IN NS i.root-servers.net
         ;; Authority:
         ;; Additional:
         */
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x28d3, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 13, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 13)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        
        let expectedQuestion = QuestionSection(host: ".", type: .NS, CLASS: .internet)
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        
        let expectedAnswers: [ResourceRecord] = [
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "e.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "b.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "d.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "f.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "g.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "c.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "a.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "m.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "l.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "j.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "k.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "h.root-servers.net."),
            ResourceRecord(name: ".", ttl: 4545, Class: DNSClass.internet, type: DNSRecordType.NS, value: "i.root-servers.net."),
        ]
        
        for i in 0..<parsedAnswer.Authority.count {
            #expect(expectedAnswers[i] == parsedAnswer.Answer[i])
        }
    }
    
    /// Response from a server pointing to the ns to query
    @Test func notAuthoritative() throws {
        // Using: k.root-servers.net    193.0.14.129, 2001:7fd::1    RIPE NCC
        
        let data: Data = Data([
            0x78, 0x2c, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1a,
            0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, 0x03, 0x6e, 0x65,
            0x74, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x14, 0x01, 0x61, 0x0c, 0x67, 0x74, 0x6c,
            0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65,
            0x74, 0x00, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0x01, 0x69, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x6a, 0xc0, 0x2c, 0xc0, 0x15,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x62,
            0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0x01, 0x6c, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x6d, 0xc0, 0x2c, 0xc0, 0x15,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x65,
            0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0x01, 0x64, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x68, 0xc0, 0x2c, 0xc0, 0x15,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x66,
            0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0x01, 0x67, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x63, 0xc0, 0x2c, 0xc0, 0x15,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x6b,
            0xc0, 0x2c, 0xc0, 0x8a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0xc0, 0x37, 0x53, 0x1e, 0xc0, 0x7a, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x29, 0xa2, 0x1e, 0xc0, 0xfa,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x34,
            0xb2, 0x1e, 0xc0, 0x5a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0xc0, 0x30, 0x4f, 0x1e, 0xc0, 0x4a, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x2b, 0xac, 0x1e, 0xc0, 0xba,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x36,
            0x70, 0x1e, 0xc0, 0xda, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0xc0, 0x2a, 0x5d, 0x1e, 0xc0, 0xca, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x23, 0x33, 0x1e, 0xc0, 0x9a,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x0c,
            0x5e, 0x1e, 0xc0, 0xaa, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0xc0, 0x1f, 0x50, 0x1e, 0xc0, 0xea, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x1a, 0x5c, 0x1e, 0xc0, 0x6a,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x21,
            0x0e, 0x1e, 0xc0, 0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x04, 0xc0, 0x05, 0x06, 0x1e, 0xc0, 0x8a, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x01, 0xb1, 0xf9,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x7a,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01,
            0x05, 0x00, 0xd9, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x30, 0xc0, 0xfa, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x0d, 0x2d, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x5a, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x70, 0x94,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x4a,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01,
            0x05, 0x03, 0x39, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x30, 0xc0, 0xba, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x08, 0xcc, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xda, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xee, 0xa3,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xca,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01,
            0x05, 0x03, 0xd4, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x30, 0xc0, 0x9a, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x1c, 0xa1, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xaa, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x85, 0x6e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xea,
            0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01,
            0x05, 0x03, 0x83, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x30, 0xc0, 0x6a, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00,
            0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x23, 0x1d, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x30, 0xc0, 0x2a, 0x00, 0x1c, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xa8, 0x3e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        // Data generated by SwiftDNS and verified
        // The data from the root server doesn't have as much compression
        let compressedData: Data = Data([
            0x78, 0x2c, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1a,
            0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, 0x03, 0x6e, 0x65,
            0x74, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01,
            0x00, 0x02, 0xa3, 0x00, 0x00, 0x11, 0x01, 0x61, 0x0c, 0x67, 0x74, 0x6c,
            0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0xc0, 0x15, 0xc0,
            0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01,
            0x69, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0x01, 0x6a, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x62, 0xc0, 0x2c, 0xc0,
            0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01,
            0x6c, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0x01, 0x6d, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x65, 0xc0, 0x2c, 0xc0,
            0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01,
            0x64, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0x01, 0x68, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x66, 0xc0, 0x2c, 0xc0,
            0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01,
            0x67, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0x01, 0x63, 0xc0, 0x2c, 0xc0, 0x15, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0x01, 0x6b, 0xc0, 0x2c, 0xc0,
            0x87, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0,
            0x37, 0x53, 0x1e, 0xc0, 0x77, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0xc0, 0x29, 0xa2, 0x1e, 0xc0, 0xf7, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x34, 0xb2, 0x1e, 0xc0,
            0x57, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0,
            0x30, 0x4f, 0x1e, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0xc0, 0x2b, 0xac, 0x1e, 0xc0, 0xb7, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x36, 0x70, 0x1e, 0xc0,
            0xd7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0,
            0x2a, 0x5d, 0x1e, 0xc0, 0xc7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0xc0, 0x23, 0x33, 0x1e, 0xc0, 0x97, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x0c, 0x5e, 0x1e, 0xc0,
            0xa7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0,
            0x1f, 0x50, 0x1e, 0xc0, 0xe7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x04, 0xc0, 0x1a, 0x5c, 0x1e, 0xc0, 0x67, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0, 0x21, 0x0e, 0x1e, 0xc0,
            0x2a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x04, 0xc0,
            0x05, 0x06, 0x1e, 0xc0, 0x87, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x01, 0xb1, 0xf9, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x77, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0xd9,
            0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0,
            0xf7, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20,
            0x01, 0x05, 0x03, 0x0d, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x30, 0xc0, 0x57, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x02, 0x70, 0x94, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0x47, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x39,
            0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0,
            0xb7, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20,
            0x01, 0x05, 0x02, 0x08, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x30, 0xc0, 0xd7, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xee, 0xa3, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xc7, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xd4,
            0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0,
            0x97, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20,
            0x01, 0x05, 0x02, 0x1c, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x30, 0xc0, 0xa7, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x85, 0x6e, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0, 0xe7, 0x00, 0x1c, 0x00,
            0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0x83,
            0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0xc0,
            0x67, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x10, 0x20,
            0x01, 0x05, 0x03, 0x23, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x30, 0xc0, 0x2a, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x02, 0xa3,
            0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x03, 0xa8, 0x3e, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30,
        ])
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == compressedData)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x782c, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 13, ARCOUNT: 26)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 13)
        #expect(parsedAnswer.Additional.count == 26)
        
        
        let expectedQuestion = QuestionSection(host: "as209245.net.", type: .AAAA, CLASS: .internet)
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        
        let expectedNS: [ResourceRecord] = [
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "a.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "i.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "j.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "b.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "l.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "m.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "e.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "d.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "h.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "f.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "g.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "c.gtld-servers.net."),
            ResourceRecord(name: "net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.NS, value: "k.gtld-servers.net."),
        ]
        
        for i in 0..<parsedAnswer.Authority.count {
            #expect(expectedNS[i] == parsedAnswer.Authority[i])
        }
        
        let expectedAR: [ResourceRecord] = [
            ResourceRecord(name: "m.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.55.83.30"),
            ResourceRecord(name: "l.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.41.162.30"),
            ResourceRecord(name: "k.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.52.178.30"),
            ResourceRecord(name: "j.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.48.79.30"),
            ResourceRecord(name: "i.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.43.172.30"),
            ResourceRecord(name: "h.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.54.112.30"),
            ResourceRecord(name: "g.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.42.93.30"),
            ResourceRecord(name: "f.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.35.51.30"),
            ResourceRecord(name: "e.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.12.94.30"),
            ResourceRecord(name: "d.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.31.80.30"),
            ResourceRecord(name: "c.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.26.92.30"),
            ResourceRecord(name: "b.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.33.14.30"),
            ResourceRecord(name: "a.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.A, value: "192.5.6.30"),
            
            ResourceRecord(name: "m.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:501:b1f9:0:0:0:0:30"),
            ResourceRecord(name: "l.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:500:d937:0:0:0:0:30"),
            ResourceRecord(name: "k.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:d2d:0:0:0:0:30"),
            ResourceRecord(name: "j.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:502:7094:0:0:0:0:30"),
            ResourceRecord(name: "i.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:39c1:0:0:0:0:30"),
            ResourceRecord(name: "h.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:502:8cc:0:0:0:0:30"),
            ResourceRecord(name: "g.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:eea3:0:0:0:0:30"),
            ResourceRecord(name: "f.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:d414:0:0:0:0:30"),
            ResourceRecord(name: "e.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:502:1ca1:0:0:0:0:30"),
            ResourceRecord(name: "d.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:500:856e:0:0:0:0:30"),
            ResourceRecord(name: "c.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:83eb:0:0:0:0:30"),
            ResourceRecord(name: "b.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:231d:0:0:0:2:30"),
            ResourceRecord(name: "a.gtld-servers.net.", ttl: 172800, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2001:503:a83e:0:0:0:2:30"),
        ]
        
        for i in 0..<parsedAnswer.Additional.count {
            #expect(expectedAR[i] == parsedAnswer.Additional[i])
        }
    }
    
    // MARK: Invalid Responses
    
    @Test func receivedHTML() throws {
        // https://google.com/teapot
        
        let data: Data = Data([
            0x3c, 0x21, 0x64, 0x6f, 0x63, 0x74, 0x79, 0x70, 0x65, 0x20, 0x68, 0x74,
            0x6d, 0x6c, 0x3e, 0x3c, 0x68, 0x74, 0x6d, 0x6c, 0x20, 0x6c, 0x61, 0x6e,
            0x67, 0x3d, 0x22, 0x65, 0x6e, 0x22, 0x3e, 0x20, 0x3c, 0x73, 0x63, 0x72,
            0x69, 0x70, 0x74, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x66,
            0x30, 0x47, 0x44, 0x4e, 0x6b, 0x6d, 0x32, 0x6c, 0x76, 0x77, 0x61, 0x5f,
            0x4c, 0x66, 0x6a, 0x46, 0x67, 0x57, 0x77, 0x4c, 0x77, 0x22, 0x3e, 0x28,
            0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x28, 0x48, 0x29, 0x7b,
            0x48, 0x2e, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
            0x48, 0x2e, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x4e, 0x61, 0x6d, 0x65, 0x2e,
            0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x28, 0x2f, 0x5c, 0x62, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x5c, 0x62, 0x2f, 0x2c, 0x27, 0x67, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x2d, 0x6a, 0x73, 0x27, 0x29, 0x7d, 0x29, 0x28,
            0x64, 0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x2e, 0x64, 0x6f, 0x63,
            0x75, 0x6d, 0x65, 0x6e, 0x74, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74,
            0x29, 0x3c, 0x2f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e, 0x20, 0x3c,
            0x6d, 0x65, 0x74, 0x61, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74,
            0x3d, 0x22, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x22, 0x3e, 0x20, 0x3c, 0x6d,
            0x65, 0x74, 0x61, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x3d,
            0x22, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x2d, 0x73, 0x63, 0x61,
            0x6c, 0x65, 0x3d, 0x31, 0x2c, 0x20, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x75,
            0x6d, 0x2d, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x3d, 0x31, 0x2c, 0x20, 0x77,
            0x69, 0x64, 0x74, 0x68, 0x3d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d,
            0x77, 0x69, 0x64, 0x74, 0x68, 0x22, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x3d,
            0x22, 0x76, 0x69, 0x65, 0x77, 0x70, 0x6f, 0x72, 0x74, 0x22, 0x3e, 0x20,
            0x3c, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3e, 0x45, 0x72, 0x72, 0x6f, 0x72,
            0x20, 0x34, 0x31, 0x38, 0x20, 0x28, 0x49, 0x26, 0x23, 0x38, 0x32, 0x31,
            0x37, 0x3b, 0x6d, 0x20, 0x61, 0x20, 0x74, 0x65, 0x61, 0x70, 0x6f, 0x74,
            0x29, 0x21, 0x3f, 0x3c, 0x2f, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x3e, 0x20,
            0x3c, 0x6c, 0x69, 0x6e, 0x6b, 0x20, 0x68, 0x72, 0x65, 0x66, 0x3d, 0x22,
            0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x73, 0x74, 0x61, 0x74, 0x69,
            0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x65, 0x61, 0x70, 0x6f, 0x74,
            0x2f, 0x74, 0x65, 0x61, 0x70, 0x6f, 0x74, 0x2e, 0x6d, 0x69, 0x6e, 0x2e,
            0x63, 0x73, 0x73, 0x22, 0x20, 0x72, 0x65, 0x6c, 0x3d, 0x22, 0x73, 0x74,
            0x79, 0x6c, 0x65, 0x73, 0x68, 0x65, 0x65, 0x74, 0x22, 0x20, 0x6e, 0x6f,
            0x6e, 0x63, 0x65, 0x3d, 0x22, 0x66, 0x30, 0x47, 0x44, 0x4e, 0x6b, 0x6d,
            0x32, 0x6c, 0x76, 0x77, 0x61, 0x5f, 0x4c, 0x66, 0x6a, 0x46, 0x67, 0x57,
            0x77, 0x4c, 0x77, 0x22, 0x3e, 0x20, 0x3c, 0x61, 0x20, 0x68, 0x72, 0x65,
            0x66, 0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
            0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, 0x2f, 0x22, 0x3e, 0x3c, 0x73, 0x70, 0x61, 0x6e, 0x20, 0x61, 0x72,
            0x69, 0x61, 0x2d, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x3d, 0x22, 0x47, 0x6f,
            0x6f, 0x67, 0x6c, 0x65, 0x22, 0x20, 0x69, 0x64, 0x3d, 0x22, 0x6c, 0x6f,
            0x67, 0x6f, 0x22, 0x3e, 0x3c, 0x2f, 0x73, 0x70, 0x61, 0x6e, 0x3e, 0x3c,
            0x2f, 0x61, 0x3e, 0x20, 0x3c, 0x70, 0x3e, 0x3c, 0x62, 0x3e, 0x34, 0x31,
            0x38, 0x2e, 0x3c, 0x2f, 0x62, 0x3e, 0x20, 0x3c, 0x69, 0x6e, 0x73, 0x3e,
            0x49, 0x26, 0x23, 0x38, 0x32, 0x31, 0x37, 0x3b, 0x6d, 0x20, 0x61, 0x20,
            0x74, 0x65, 0x61, 0x70, 0x6f, 0x74, 0x2e, 0x3c, 0x2f, 0x69, 0x6e, 0x73,
            0x3e, 0x3c, 0x2f, 0x70, 0x3e, 0x20, 0x3c, 0x70, 0x3e, 0x54, 0x68, 0x65,
            0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x65,
            0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x69,
            0x73, 0x20, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x20, 0x61, 0x6e, 0x64, 0x20,
            0x73, 0x74, 0x6f, 0x75, 0x74, 0x2e, 0x20, 0x3c, 0x69, 0x6e, 0x73, 0x3e,
            0x54, 0x69, 0x70, 0x20, 0x6d, 0x65, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20,
            0x61, 0x6e, 0x64, 0x20, 0x70, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x65, 0x20,
            0x6f, 0x75, 0x74, 0x2e, 0x3c, 0x2f, 0x69, 0x6e, 0x73, 0x3e, 0x3c, 0x2f,
            0x70, 0x3e, 0x20, 0x3c, 0x64, 0x69, 0x76, 0x20, 0x69, 0x64, 0x3d, 0x22,
            0x74, 0x65, 0x61, 0x73, 0x65, 0x74, 0x22, 0x3e, 0x3c, 0x64, 0x69, 0x76,
            0x20, 0x69, 0x64, 0x3d, 0x22, 0x74, 0x65, 0x61, 0x62, 0x6f, 0x74, 0x22,
            0x3e, 0x3c, 0x2f, 0x64, 0x69, 0x76, 0x3e, 0x3c, 0x64, 0x69, 0x76, 0x20,
            0x69, 0x64, 0x3d, 0x22, 0x74, 0x65, 0x61, 0x63, 0x75, 0x70, 0x22, 0x3e,
            0x3c, 0x2f, 0x64, 0x69, 0x76, 0x3e, 0x3c, 0x2f, 0x64, 0x69, 0x76, 0x3e,
            0x20, 0x3c, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x20, 0x73, 0x72, 0x63,
            0x3d, 0x22, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x73, 0x74, 0x61,
            0x74, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x74, 0x65, 0x61, 0x70,
            0x6f, 0x74, 0x2f, 0x74, 0x65, 0x61, 0x70, 0x6f, 0x74, 0x2e, 0x6d, 0x69,
            0x6e, 0x2e, 0x6a, 0x73, 0x22, 0x20, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x3d,
            0x22, 0x66, 0x30, 0x47, 0x44, 0x4e, 0x6b, 0x6d, 0x32, 0x6c, 0x76, 0x77,
            0x61, 0x5f, 0x4c, 0x66, 0x6a, 0x46, 0x67, 0x57, 0x77, 0x4c, 0x77, 0x22,
            0x3e, 0x3c, 0x2f, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e, 0x20, 0x3c,
            0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e
        ])
        
        #expect(throws: DNSError.invalidData("offset out of bounds for type and class"), performing: {
            let _ = try DNSMessage(data: data)
        })
    }
    
    // MARK: EDNS
    
    @Test func aaaa_edns_query() throws {
        // AAAA query with edns data. From dig
        // ff780120000100000000000106676f6f676c6503636f6d00001c00010000291000000000000000

        let data: Data = Data([
            // Header
            0xff, 0x78, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Question
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x1c, 0x00, 0x01,
            // OPT Record
            0x00,                       // Null label
            0x00, 0x29,                 // Type = 41
            0x10, 0x00,                 // requestor's UDP payload size (Class)
            0x00, 0x00, 0x00, 0x00,     // extended RCODE and flags (TTL)
            0x00, 0x00,                 // RLENGTH
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print("----------------------------\nOutput:\n\(parsedOut.description)\n\nReference:\n\(parsedAnswer.description)\n----------------------------")
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0, z: 2)
        let expectedHeader = DNSHeader(id: 0xff78, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 1)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .AAAA, CLASS: .internet)
        
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [])
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        // print("\(ednsRecord.description)")
        
        #expect(parsedAnswer.header == expectedHeader)
        #expect(parsedAnswer.header.flags == expectedFlags)
        
        #expect(parsedAnswer.header.QDCOUNT == 1)
        #expect(parsedAnswer.header.ANCOUNT == 0)
        #expect(parsedAnswer.header.NSCOUNT == 0)
        #expect(parsedAnswer.header.ARCOUNT == 1)
        #expect(ednsRecord == expectedEDNS)
        
        #expect(parsedAnswer.Question.first! == expectedQuestion)
    }
    
    @Test func aaaa_edns_response() throws {
        // ff788180000100010000000106676f6f676c6503636f6d00001c0001c00c001c00010000005b00102607f8b04012081d000000000000200e00002904d0000000000000

        let data: Data = Data([
            0xff, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x5b, 0x00, 0x10, 0x26, 0x07, 0xf8, 0xb0, 0x40, 0x12, 0x08, 0x1d,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e, 0x00, 0x00, 0x29, 0x04,
            0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0xff78, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .AAAA, CLASS: .internet)
        
        // google.com.        91    IN    AAAA    2607:f8b0:4012:81d::200e
        let expectedAnswer = ResourceRecord(name: "google.com.", ttl: 91, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2607:f8b0:4012:81d:0:0:0:200e")
        
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [])
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        guard let firstAnswer = parsedAnswer.Answer.first else {
            Issue.record("First answer is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(ednsRecord == expectedEDNS)
        #expect(firstAnswer == expectedAnswer)
        #expect(firstQuestion == expectedQuestion)
        
    }
    
    // Should this one be kept? **
    @Test func aa_clientSubnet_request() throws {
        // 1e4e0120000100000000000106676f6f676c6503636f6d0000010001000029100000000000000b0008000700011500bd9f68

        let data: Data = Data([
            0x1e, 0x4e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x15, 0x00, 0xbd,
            0x9f, 0x68,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        // // #expect(dataOut == data)
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        print("----------------------------\nReference:\n\(parsedAnswer.description)\n")
        let parsedOut = try DNSMessage(data: dataOut)
        print("\nOutput:\n\(parsedOut.description)\n----------------------------")
        #expect(parsedAnswer == parsedOut)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x1e4e, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .A, CLASS: .internet)
        /*
        EXT_RCODE=0, VERSION=0, DO=false
        OPTIONS: Client Subnet: Family=1, SourceMask=21, ScopeMask=0, IP=189.159.104.0
         */
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [EDNSOption(family: 1, IP: "189.159.104.0", sourceMask: 21, scopeMask: 0)], udpPayloadSize: 4096)
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(ednsRecord == expectedEDNS)
        #expect(firstQuestion == expectedQuestion)
    }
    
    @Test func a_clientSubnet_response() throws {
        // 1e4e8180000100010000000106676f6f676c6503636f6d0000010001c00c00010001000000af00048efab00e000029020000000000000b0008000700011511bd9f68

        let data: Data = Data([
            0x1e, 0x4e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xaf, 0x00, 0x04, 0x8e, 0xfa, 0xb0, 0x0e, 0x00, 0x00, 0x29, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x07, 0x00,
            0x01, 0x15, 0x11, 0xbd, 0x9f, 0x68,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x1e4e, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .A, CLASS: .internet)
        
        // google.com.        175    IN    A    142.250.176.14
        let expectedAnswer = ResourceRecord(name: "google.com.", ttl: 175, Class: DNSClass.internet, type: DNSRecordType.A, value: "142.250.176.14")
        
        guard let firstAnswer = parsedAnswer.Answer.first else {
            Issue.record("First answer is nil")
            return
        }
        
        /*
        EXT_RCODE=0, VERSION=0, DO=false
        OPTIONS: Client Subnet: Family=1, SourceMask=21, ScopeMask=17, IP=189.159.104.0
        */
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [EDNSOption(family: 1, IP: "189.159.104.0", sourceMask: 21, scopeMask: 17)], udpPayloadSize: 512)
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(firstAnswer == expectedAnswer)
        #expect(ednsRecord == expectedEDNS)
    }
    
    @Test func aaaa_clientSubnet_response() throws {
        // 13b08180000100010000000106676f6f676c6503636f6d00001c0001c00c001c00010000012c00102a001450400e080e000000000000200e000029020000000000000e0008000a000230312a11f2c0fff7

        let data: Data = Data([
            0x13, 0xb0, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x01, 0x2c, 0x00, 0x10, 0x2a, 0x00, 0x14, 0x50, 0x40, 0x0e, 0x08, 0x0e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e, 0x00, 0x00, 0x29, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x0a, 0x00,
            0x02, 0x30, 0x31, 0x2a, 0x11, 0xf2, 0xc0, 0xff, 0xf7,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x13b0, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "google.com.", type: .AAAA, CLASS: .internet)
        
        // google.com.        300    IN    AAAA    2a00:1450:400e:80e::200e
        let expectedAnswer = ResourceRecord(name: "google.com.", ttl: 300, Class: DNSClass.internet, type: DNSRecordType.AAAA, value: "2a00:1450:400e:80e:0:0:0:200e")
        
        guard let firstAnswer = parsedAnswer.Answer.first else {
            Issue.record("First answer is nil")
            return
        }
        
        /*
         EXT_RCODE=0, VERSION=0, DO=false
         OPTIONS: Client Subnet: Family=2, SourceMask=48, ScopeMask=49, IP=2a11:f2c0:fff7:0:0:0:0:0
         */
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [EDNSOption(family: 2, IP: "2a11:f2c0:fff7:0:0:0:0:0", sourceMask: 48, scopeMask: 49)], udpPayloadSize: 512)
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(firstAnswer == expectedAnswer)
        #expect(ednsRecord == expectedEDNS)
    }
    
    @Test func edns_cookie_response() throws {
        // 68ae850000010001000300010830313030303131300378797a00000100010830313030303131300378797a00000100010000a8c0000442e42ebd0830313030303131300378797a0000020001000151800012036e7330086173323039323435036e6574000830313030303131300378797a0000020001000151800012036e7331086173323039323435036e6574000830313030303131300378797a0000020001000151800014096e732d676c6f62616c046b6a736c03636f6d0000002904d000000000000c000a00085526d20e26f1dce8

        let data: Data = Data([
            0x68, 0xae, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x01,
            0x08, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x31, 0x30, 0x03, 0x78, 0x79,
            0x7a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x08, 0x30, 0x31, 0x30, 0x30, 0x30,
            0x31, 0x31, 0x30, 0x03, 0x78, 0x79, 0x7a, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0xa8, 0xc0, 0x00, 0x04, 0x42, 0xe4, 0x2e, 0xbd, 0x08, 0x30,
            0x31, 0x30, 0x30, 0x30, 0x31, 0x31, 0x30, 0x03, 0x78, 0x79, 0x7a, 0x00,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x12, 0x03, 0x6e,
            0x73, 0x30, 0x08, 0x61, 0x73, 0x32, 0x30, 0x39, 0x32, 0x34, 0x35, 0x03,
            0x6e, 0x65, 0x74, 0x00, 0x08, 0x30, 0x31, 0x30, 0x30, 0x30, 0x31, 0x31,
            0x30, 0x03, 0x78, 0x79, 0x7a, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01,
            0x51, 0x80, 0x00, 0x12, 0x03, 0x6e, 0x73, 0x31, 0x08, 0x61, 0x73, 0x32,
            0x30, 0x39, 0x32, 0x34, 0x35, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x08, 0x30,
            0x31, 0x30, 0x30, 0x30, 0x31, 0x31, 0x30, 0x03, 0x78, 0x79, 0x7a, 0x00,
            0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x51, 0x80, 0x00, 0x14, 0x09, 0x6e,
            0x73, 0x2d, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x04, 0x6b, 0x6a, 0x73,
            0x6c, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x10, 0x55, 0x26, 0xd2,
            0x0e, 0x26, 0xf1, 0xdc, 0xe8, 0x54, 0x16, 0xd5, 0x0f, 0x12, 0xfe, 0xda,
            0xe3,
        ])
        
        print("data:    \(data.hexEncodedString())")
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        // CoreData only uses compression when queried over UDP and when the data is smaller than the UDP max payload size
        // #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        let parsedOut = try DNSMessage(data: dataOut)
        #expect(parsedAnswer == parsedOut)
        // print(parsedAnswer.description)
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 1, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x68ae, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 1, NSCOUNT: 3, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 1)
        #expect(parsedAnswer.Authority.count == 3)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "01000110.xyz.", type: .A, CLASS: .internet)
        
        /*
         ;; ANSWER SECTION:
         01000110.xyz.        43200    IN    A    66.228.46.189

         ;; AUTHORITY SECTION:
         01000110.xyz.        86400    IN    NS    ns0.as209245.net.
         01000110.xyz.        86400    IN    NS    ns1.as209245.net.
         01000110.xyz.        86400    IN    NS    ns-global.kjsl.com.
         */
        let expectedAnswer0 = ResourceRecord(name: "01000110.xyz.", ttl: 86400, Class: .internet, type: .NS, value: "ns0.as209245.net.")
        let expectedAnswer1 = ResourceRecord(name: "01000110.xyz.", ttl: 86400, Class: .internet, type: .NS, value: "ns1.as209245.net.")
        let expectedAnswer2 = ResourceRecord(name: "01000110.xyz.", ttl: 86400, Class: .internet, type: .NS, value: "ns-global.kjsl.com.")
        
        /*
         EXT_RCODE=0, VERSION=0, DO=false
         OPTIONS: "
        */
        let expectedEDNS = EDNSMessage(extendedRcode: 0, doBit: false, options: [EDNSOption(clientCookie: "5526d20e26f1dce8", serverCookie: "5416d50f12fedae3")])
        
        guard let ednsRecord = parsedAnswer.EDNSData else {
            Issue.record("EDNS data is nil")
            return
        }
        
        guard let firstQuestion = parsedAnswer.Question.first else {
            Issue.record("First question is nil")
            return
        }
        
        #expect(firstQuestion == expectedQuestion)
        #expect(parsedAnswer.Authority[0] == expectedAnswer0)
        #expect(parsedAnswer.Authority[1] == expectedAnswer1)
        #expect(parsedAnswer.Authority[2] == expectedAnswer2)
        #expect(ednsRecord == expectedEDNS)
    }
    
    @Test func edns_ExtendedDNSError() async throws {
        let data: Data = Data([
            0xcf, 0x7a, 0x81, 0x82, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x08,
            0x6e, 0x6f, 0x74, 0x2d, 0x61, 0x75, 0x74, 0x68,                                             // not-auth
            0x13,
            0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x2d, 0x64, 0x6e, 0x73, 0x2d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73,  // extended-dns-errors
            0x03,
            0x63, 0x6f, 0x6d,                                                                           // com
            0x00,
            0x00, 0x01,
            0x00, 0x01,
            0x00,
            0x00, 0x29,                                                                                 // 41 = OPT
            0x02, 0x00,                                                                                 // UDPMaxPayloadSize = 512
            0x00, 0x00, 0x00, 0x00,
            0x00, 0xd7,                                                                                 // RDLength = 215
            
            0x00, 0x03,                                                                                 // First Option code 3 = NSID
            0x00, 0x09,                                                                                 // Option length = 9
            0x67, 0x70, 0x64, 0x6e, 0x73, 0x2d, 0x61, 0x6d, 0x73,                                       // gpdns-ams
            
            0x00, 0x0f,                                                                                 // Second Option Code 15 = EDE
            0x00, 0x6b,                                                                                 // Option Length = 107
            0x00, 0x00,                                                                                 // Extended DNS Error = other
            0x5b, 0x36, 0x35, 0x2e, 0x32, 0x31, 0x2e, 0x35, 0x31, 0x2e, 0x31, 0x31, 0x37, 0x5d, 0x20,   // "[65.21.51.117]"
            0x4c, 0x61, 0x6d, 0x65, 0x20, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e,   // "Lame delegation"
            0x20, 0x61, 0x74, 0x20, 0x6e, 0x6f, 0x74, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x65, 0x78,   // " at not-auth.ex"
            0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x2d, 0x64, 0x6e, 0x73, 0x2d, 0x65, 0x72, 0x72, 0x6f,   // "tended-dns-erro"
            0x72, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x2d,   // "rs.com for not-"
            0x61, 0x75, 0x74, 0x68, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x2d, 0x64,   // "auth.extended-d"
            0x6e, 0x73, 0x2d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61,   // "ns-errors.com/a"
            
            0x00, 0x0f,                                                                                 // Third Option Code 15 = EDE
            0x00, 0x57,                                                                                 // Option Length = 87
            0x00, 0x16,                                                                                 // Extended DNS Error = noReachableAuthority
            0x41, 0x74, 0x20, 0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6e,   // "At delegation n"
            0x6f, 0x74, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65,   // "ot-auth.extende"
            0x64, 0x2d, 0x64, 0x6e, 0x73, 0x2d, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x2e, 0x63, 0x6f,   // "d-dns-errors.co"
            0x6d, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x2e,   // "m for not-auth."
            0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x2d, 0x64, 0x6e, 0x73, 0x2d, 0x65, 0x72,   // "extended-dns-er"
            0x72, 0x6f, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61                                  // "rors.com/a"
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: .ServFail)
        let expectedHeader = DNSHeader(id: 0xcf7a, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        #expect(parsedAnswer.EDNSData != nil)
        #expect(parsedAnswer.EDNSData?.options.count == 3)
        
    
        let expectedOption0 = EDNSOption(NSID: "gpdns-ams")
        let expectedOption1 = EDNSOption(ExtendedDNSError: .otherError, ExtraText: "[65.21.51.117] Lame delegation at not-auth.extended-dns-errors.com for not-auth.extended-dns-errors.com/a")
        let expectedOption2 = EDNSOption(ExtendedDNSError: .noReachableAuthority, ExtraText: "At delegation not-auth.extended-dns-errors.com for not-auth.extended-dns-errors.com/a")
        
        #expect(parsedAnswer.EDNSData?.options[0] == expectedOption0)
        #expect(parsedAnswer.EDNSData?.options[1] == expectedOption1)
        #expect(parsedAnswer.EDNSData?.options[2] == expectedOption2)
    }
    
    /// Tests parsing a DNSMessage that is only a DNS Header
    @Test func onlyHeader() throws {

        let data: Data = Data([
            0xe8, 0x88, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        
        let parsedAnswer = try DNSMessage(data: data)
        
        let dataOut = try parsedAnswer.toData()
        #expect(dataOut == data)
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // print(parsedAnswer.description)
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, rcode: 0)
        let expectedHeader = DNSHeader(id: 0xe888, flags: expectedFlags, QDCOUNT: 0, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 0)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
    }
}
