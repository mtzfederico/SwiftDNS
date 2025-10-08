//
//  EDNSOption.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-06
// 

import Testing
import Foundation
@testable import SwiftDNS

struct EDNS {

    @Test func testClientSubnet() async throws {
        //

        let data: Data = Data([
            0x1e, 0x4e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x15, 0x00, 0xbd,
            0x9f, 0x68,
        ])
        
        var offset: Int = 0
        let parsedAnswer = EDNSOption(data: data, offset: &offset)
        
        let dataOut = try parsedAnswer.toData()
        // // #expect(dataOut == data)
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        print("----------------------------\nReference:\n\(parsedAnswer.description)\n")
        let parsedOut = try DNSMessage(data: dataOut)
        print("\nOutput:\n\(parsedOut.description)\n----------------------------")
        #expect(parsedAnswer == parsedOut)
        
        
        /*
         1e 4e 01 20 00 01 00 00 00 00 00 01
         
         06
         67 6f 6f 67 6c 65
         03
         63 6f 6d
         00
         00 01
         00 01
         
         00
         00 29
         10 00
         00 00 00 00
         00 11
         
         00 08 00 00 00 00 00 00 00 07 01 00
         15 15 bd 9f 68
         */
        
        /*
         1e 4e 01 20 00 01 00 00 00 00 00 01
         
         06
         67 6f 6f 67 6c 65
         03
         63 6f 6d
         00
         00 01
         00 01
         
         00
         00 29
         10 00
         00 00 00 00
         00 11
         
         00 08
         00 00
         00 00  // Family
         00
         00
         00 07 01 00
         
         15 15 bd 9f 68
         */
        
        // -------
        
        let expectedFlags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        let expectedHeader = DNSHeader(id: 0x1e4e, flags: expectedFlags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 1)
        
        #expect(parsedAnswer.header == expectedHeader)
        
        #expect(parsedAnswer.Question.count == 1)
        #expect(parsedAnswer.Answer.count == 0)
        #expect(parsedAnswer.Authority.count == 0)
        #expect(parsedAnswer.Additional.count == 0)
        
        let expectedQuestion = QuestionSection(host: "google.com", type: .A, CLASS: .internet)
        /*
        EXT_RCODE=0, VERSION=0, DO=false
        OPTIONS: Client Subnet: Family=1, SourceMask=21, ScopeMask=0, IP=189.159.104.0
         */
        let expectedEDNS = EDNSMessage(extendedRcode: 0, version: 0, zField: 0, doBit: false, options: [EDNSOption(code: .ClientSubnet, values: ["Family": "1", "SourceMask": "21", "ScopeMask": "0", "IP": "189.159.104.0"])], udpPayloadSize: 4096)
        
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

}
