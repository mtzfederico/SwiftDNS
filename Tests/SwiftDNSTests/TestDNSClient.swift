//
//  TestDNSClient.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-12-25
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestDNSClient {
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
        
        #expect(throws: DNSError.invalidData("Name pointer out of bounds"), performing: {
            let _ = try DNSClient.parseDomainName(data: data, offset: 0)
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
        
        #expect(throws: DNSError.invalidData("Name pointer references itself"), performing: {
            let _ = try DNSClient.parseDomainName(data: data, offset: 0)
        })
    }
}
