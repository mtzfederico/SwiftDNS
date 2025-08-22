//
//  TestDataExtension.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestDataExtension {
    let dnsCoder = DNSCoder()
    
    @Test func readUInt16() throws {
        let rawFlags: Data = Data([0x01, 0x03, 0x05, 0x07])
        let rawValue = try rawFlags.readUInt16(at: 0)
        
        #expect(rawValue == 0x0103)
        
        let rawValue1 = try rawFlags.readUInt16(at: 2)
        
        #expect(rawValue1 == 0x0507)
    }
}
