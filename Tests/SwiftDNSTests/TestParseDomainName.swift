//
//  TestParseDomainName.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-12-25
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestParseDomainName {
    /// Tries to parse a DNS label with a compression pointer outside of the bounds of the data
    @Test func parseCompressionOutOfBounds() async throws {
        let data: Data = Data([
            0x03,
            0x77, 0x77, 0x77,                   // www
            0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0xc0, 0x1e,                         // Pointer to 30
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.invalidData(msg: "Name pointer out of bounds", data: data), performing: {
            let _ = try DNSMessage.parseDomainName(data: data, offset: 0)
        })
    }

    /// Tries to parse a DNS label with a compression pointer referencing itself
    @Test func parseSelfCompression() async throws {
        let data: Data = Data([
            0x03,
            0x77, 0x77, 0x77,                   // www
            0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0xc0, 0x0b,                         // Pointer to self
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.invalidData(msg: "Name pointer references itself", data: data), performing: {
            let _ = try DNSMessage.parseDomainName(data: data, offset: 0)
        })
    }
    
    /// Tries to parse a DNS label with a compression pointer referencing a pointer that points back to itself.
    /// A --> B
    @Test func parseLoopCompression() async throws {
        let data: Data = Data([
            0xc0, 0x02,                         // pointer to 2
            0xc0, 0x00,                         // pointer to 0
            0x00,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0xc0, 0x00,                         // Pointer to 0
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.namePointerLoop(at: 2, to: 0), performing: {
            let (name, length) = try DNSMessage.parseDomainName(data: data, offset: 0)
            print("\(#function) name: \(name), length: \(length)")
        })
    }
    
    /// Tries to parse a DNS label with a compression pointer referencing a pointer that points back to itself.
    /// A --> B --> C -->  A
    @Test func parseCompressionChain() async throws {
        let data: Data = Data([
            0xc0, 0x04,                         // pointer to 4
            0xc0, 0x00,                         // pointer to 0
            0xc0, 0x02,                         // Pointer to 2
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.namePointerLoop(at: 2, to: 0), performing: {
            let (name, length) = try DNSMessage.parseDomainName(data: data, offset: 0)
            print("\(#function) name: \(name), length: \(length)")
        })
    }
    
    /*
    /// Makes a few requests using UDP
    @Test func tryUDPQuery() async throws {
        for i in 1...5 {
            print("Sending query #\(i)")
            let client = DNSClient(server: "9.9.9.9", connectionType: .dnsOverUDP)
            
            let result = try await client.query(host: "ipv4only.arpa", type: .A)
            
            print(result.description)
            
            #expect(result.header.ANCOUNT == 2)
            try await Task.sleep(nanoseconds: 5_452_000_000)
        }
    }*/
}


/*
 /// Tries to parse a DNS label with a compression pointer referencing a pointer that points back to itself.
    /// A --> B
    @Test func parseLoopCompression() async throws {
        let data: Data = Data([
            0xc0, 0x0a,                         // pointer to 10
            0x06,
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
            0xc0, 0x01,                         // Pointer to 1
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.invalidData("Name pointer out of bounds"), performing: {
            let (name, length) = try DNSClient.parseDomainName(data: data, offset: 0)
            print("\(#function) name: \(name), length: \(length)")
        })
    }
    
    /// Tries to parse a DNS label with a compression pointer referencing a pointer that points back to itself.
    /// A --> B --> C -->  A
    @Test func parseCompressionChain() async throws {
        let data: Data = Data([
            0xc0, 0x05,                         // pointer to 5
            0xc0, 0x01,                         // pointer to 1
            0xc0, 0x03,                         // Pointer to 3
            0x00,
            
            0x00, 0x01,                         // TYPE 1 = A
            0x00, 0x01,                         // class IN
            0x00, 0x01, 0x4f, 0x4f,             // ttl = 85839
            0x00, 0x04,                         // rdlength = 4
            0xd8, 0xef, 0x24, 0x0a              // 216.239.36.10
        ])
        
        #expect(throws: DNSError.namePointerLoop(at: 12, to: 2), performing: {
            let (name, length) = try DNSClient.parseDomainName(data: data, offset: 0)
            print("\(#function) name: \(name), length: \(length)")
        })
    }
 */
