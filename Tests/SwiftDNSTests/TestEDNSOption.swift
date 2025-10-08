//
//  TestEDNSOption.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-06
// 

import Testing
import Foundation
@testable import SwiftDNS

struct TestEDNSOption {

    @Test func testIPv4ClientSubnet() async throws {
        let data: Data = Data([
            0x00, 0x08,         // OP Code = 8
            0x00, 0x07,         // OP Length
            0x00, 0x01,         // Family = 1
            0x15,               // Source Prefix Length. 0x15 = /21
            0x00,               // Scope Prefix Length
            0xbd, 0x9f, 0x68    // Address = 189.159.104
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        // print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .ClientSubnet, values: ["Family": "1", "SourceMask": "21", "ScopeMask": "0", "IP": "189.159.104.0"])
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testIPv6ClientSubnet() async throws {
        let data: Data = Data([
            0x00, 0x08,                         // OP Code = 8
            0x00, 0x0a,                         // OP Length = 10
            0x00, 0x02,                         // Family = 2
            0x30,                               // Source Prefix Length. 0x30 = /48
            0x00,                               // Scope Prefix Length
            0x2a, 0x11, 0xf2, 0xc0, 0xff, 0xf7  // Address = 2a11:f2c0:fff7:0:0:0:0:0
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .ClientSubnet, values: ["Family": "2", "SourceMask": "48", "ScopeMask": "0", "IP": "2a11:f2c0:fff7:0:0:0:0:0"])
        
        #expect(parsedOption == expectedOption)
    }

    @Test func testOnlyClientCookie() async throws {
        let data: Data = Data([
            0x00, 0x0a,                                     // OP Code = 10
            0x00, 0x08,                                     // OP Length = 8
            0x55, 0x26, 0xd2, 0x0e, 0x26, 0xf1, 0xdc, 0xe8, // Client Cookie
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .COOKIE, values: ["Client": "5526d20e26f1dce8", "Server": "None"])
        
        #expect(parsedOption == expectedOption)
    }
    
    // Test a server cookie with the minimum size (8 bytes)
    @Test func testMinServerCookie() async throws {
        let data: Data = Data([
            0x00, 0x0a,                                     // OP Code = 10
            0x00, 0x10,                                     // OP Length = 16
            0x55, 0x26, 0xd2, 0x0e, 0x26, 0xf1, 0xdc, 0xe8, // Client Cookie
            0x54, 0x16, 0xd5, 0x0f, 0x12, 0xfe, 0xda, 0xe3, // Server Cookie
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .COOKIE, values: ["Client": "5526d20e26f1dce8", "Server": "5416d50f12fedae3"])
        
        #expect(parsedOption == expectedOption)
    }
    
    // Test a server cookie with the mximum size (32 bytes)
    @Test func testMaxServerCookie() async throws {
        let data: Data = Data([
            0x00, 0x0a,                                     // OP Code = 10
            0x00, 0x28,                                     // OP Length = 40
            0x55, 0x26, 0xd2, 0x0e, 0x26, 0xf1, 0xdc, 0xe8, // Client Cookie
            0x54, 0x16, 0xd5, 0x4f, 0x12, 0xfe, 0xda, 0xe3, // Server Cookie
            0x44, 0x46, 0xa5, 0x3f, 0x24, 0xfe, 0xaa, 0xf8, // Server Cookie
            0x34, 0x36, 0x02, 0x2f, 0x36, 0xfe, 0x9d, 0xc5, // Server Cookie
            0x24, 0x26, 0xf5, 0x1f, 0x48, 0xfe, 0xff, 0xb6, // Server Cookie
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        print("dataOut: \(dataOut.hexEncodedString())\ndata:    \(data.hexEncodedString())")
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .COOKIE, values: ["Client": "5526d20e26f1dce8", "Server": "5416d54f12fedae34446a53f24feaaf83436022f36fe9dc52426f51f48feffb6"])
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testKeepAlive() async throws {
        let data: Data = Data([
            0x00, 0x0b,     // OP Code = 11
            0x00, 0x02,     // OP Length = 2
            0x00, 0x05      // Timeout in in units of 100 milliseconds
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .KeepAlive, values: ["Timeout": "5"])
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testPadding() async throws {
        let data: Data = Data([
            0x00, 0x0c,                                     // OP Code = 12
            0x00, 0x10,                                     // OP Length = 16
            0x55, 0x26, 0xd2, 0x0e, 0x26, 0xf1, 0xdc, 0xe8, // Padding
            0x54, 0x16, 0xd5, 0x4f, 0x12, 0xfe, 0xda, 0xe3, // Padding
        ])
        
        var offset: Int = 0
        let parsedOption = try EDNSOption(data: data, offset: &offset)
        
        // Test encoding
        let dataOut = try parsedOption.toData()
        #expect(dataOut == data)
        
        // Test init from data generated
        var offset2: Int = 0
        let parsedOut = try EDNSOption(data: dataOut, offset: &offset2)
        #expect(parsedOption == parsedOut)
    
        let expectedOption = EDNSOption(code: .Padding, values: ["Padding": "5526d20e26f1dce85416d54f12fedae3"])
        
        #expect(parsedOption == expectedOption)
    }
    
    // ExtendedDNSError 15
    
    // MARK: Errors
    
    @Test func OPLengthTooBig() async throws {
        let data: Data = Data([
            0x00, 0x0a,                                     // OP Code = 10
            0x00, 0x40,                                     // OP Length = 64
            0x55, 0x26, 0xd2, 0x0e, 0x26, 0xf1, 0xdc, 0xe8, // Client Cookie
            0x54, 0x16, 0xd5, 0x4f, 0x12, 0xfe, 0xda, 0xe3, // Server Cookie
            0x44, 0x46, 0xa5, 0x3f, 0x24, 0xfe, 0xaa, 0xf8, // Server Cookie
            0x34, 0x36, 0x02, 0x2f, 0x36, 0xfe, 0x9d, 0xc5, // Server Cookie
            0x24, 0x26, 0xf5, 0x1f, 0x48, 0xfe, 0xff, 0xb6, // Server Cookie
        ])
        
        #expect(throws: DNSError.parsingError(DNSError.invalidData("EDNS option length out of bounds")), performing: {
            var offset: Int = 0
            let _ = try EDNSOption(data: data, offset: &offset)
        })
    }
}

