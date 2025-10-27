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
    // MARK: Test EDNSExtendedError initliazers and values
    
    @Test func EDNSExtendedErrorFromString() {
        #expect(EDNSExtendedError.allCases.count == 31)
        for type in EDNSExtendedError.allCases {
            let description = type.description
            #expect(EDNSExtendedError(description) == type)
        }
    }
    
    @Test func EDNSExtendedErrorFromValue() {
        for type in EDNSExtendedError.allCases {
            #expect(EDNSExtendedError(type.rawValue) == type)
        }
        
        // Test an unknown value
        let type128 = EDNSExtendedError.unknown(128)
        #expect(type128.description == "ExtendedError128")
        #expect(EDNSExtendedError("ExtendedError128") == type128)
    }
    
    // MARK: Test DNSRecordType initliazers and values
    
    @Test func EDNSOptionCodeFromString() {
        #expect(EDNSOptionCode.allCases.count == 13)
        for type in EDNSOptionCode.allCases {
            let description = type.description
            #expect(EDNSOptionCode(description)! == type)
        }
    }
    
    @Test func EDNSOptionCodeFromValue() {
        for type in EDNSOptionCode.allCases {
            #expect(EDNSOptionCode(type.rawValue) == type)
        }
        
        // Test an unknown value
        let type128 = EDNSOptionCode.unknown(128)
        #expect(type128.description == "OPTION128")
        #expect(EDNSOptionCode("OPTION128")! == type128)
    }

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
    
        let expectedOption = EDNSOption(family: 1, IP: "189.159.104.0", sourceMask: 21, scopeMask: 0)
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testIPv4ClientSubnetResponse() async throws {
        let data: Data = Data([
            0x00, 0x08,         // OP Code = 8
            0x00, 0x07,         // OP Length
            0x00, 0x01,         // Family = 1
            0x15,               // Source Prefix Length. 0x15 = /21
            0x11,               // Scope Prefix Length = 17
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
    
        let expectedOption = EDNSOption(family: 1, IP: "189.159.104.0", sourceMask: 21, scopeMask: 17)
        
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
    
        let expectedOption = EDNSOption(family: 2, IP: "2a11:f2c0:fff7:0:0:0:0:0", sourceMask: 48, scopeMask: 0)
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testIPv6ClientSubnetResponse() async throws {
        let data: Data = Data([
            0x00, 0x08,                         // OP Code = 8
            0x00, 0x0a,                         // OP Length = 10
            0x00, 0x02,                         // Family = 2
            0x30,                               // Source Prefix Length. 0x30 = /48
            0x31,                               // Scope Prefix Length = 49
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
    
        let expectedOption = EDNSOption(family: 2, IP: "2a11:f2c0:fff7:0:0:0:0:0", sourceMask: 48, scopeMask: 49)
        
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
    
        let expectedOption = EDNSOption(clientCookie: "5526d20e26f1dce8", serverCookie: "")
        
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
    
        let expectedOption = EDNSOption(clientCookie: "5526d20e26f1dce8", serverCookie: "5416d50f12fedae3")
        
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
    
        let expectedOption = EDNSOption(clientCookie: "5526d20e26f1dce8", serverCookie: "5416d54f12fedae34446a53f24feaaf83436022f36fe9dc52426f51f48feffb6")
        
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
    
        let expectedOption = EDNSOption(padding: try Data(hex: "5526d20e26f1dce85416d54f12fedae3"))
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testExtendedDNSError0() async throws {
        let data: Data = Data([
            0x00, 0x0f,                                     // OP Code = 15
            0x00, 0x02,                                     // OP Length = 2
            0x00, 0x11,                                     // Code 17 = filtered
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
    
        let expectedOption = EDNSOption(ExtendedDNSError: .filtered)
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testExtendedDNSError1() async throws {
        let data: Data = Data([
            0x00, 0x0f,                                     // OP Code = 15
            0x00, 0x36,                                     // OP Length = 54
            0x00, 0x11,                                     // Code 17 = filtered
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
            0x21, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6e,
            0x20, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x20, 0x65, 0x64,
            0x6E, 0x73, 0x20, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x20, 0x6d, 0x65, 0x73,
            0x73, 0x61, 0x67, 0x65,
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
    
        let expectedOption = EDNSOption(ExtendedDNSError: .filtered, ExtraText: "Hello, World! This is an extended edns error message")
        
        #expect(parsedOption == expectedOption)
    }
    
    @Test func testNSID() async throws {
        #expect(false)
    }
    
    // TODO: Test unknown option
    
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

