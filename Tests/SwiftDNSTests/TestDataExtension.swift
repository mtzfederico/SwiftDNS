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
    @Test func testhexEncodedString0() throws {
        let data: Data = Data([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        let expectedHex = "48656C6C6F2C20576F726C6421".lowercased()
        
        let hexString = data.hexEncodedString()
        #expect(hexString == expectedHex)
        
        let outData = try Data(hex: hexString)
        #expect(outData == data)
        
        #expect(String(data: data, encoding: .ascii) == "Hello, World!")
    }
    
    @Test func testhexEncodedString1() throws {
        let data: Data = Data([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21])
        let expectedHex = "48656c6c6f2c20576f726c6421"
        
        let hexString = data.hexEncodedString()
        #expect(hexString == expectedHex)
        
        let outData = try Data(hex: hexString)
        #expect(outData == data)
        
        #expect(String(data: data, encoding: .ascii) == "Hello, World!")
    }
    
    @Test func readUInt16() throws {
        let rawFlags: Data = Data([0x01, 0x03, 0x05, 0x07])
        let rawValue = try rawFlags.readUInt16(at: 0)
        
        #expect(rawValue == 0x0103)
        
        let rawValue1 = try rawFlags.readUInt16(at: 2)
        
        #expect(rawValue1 == 0x0507)
    }
}
