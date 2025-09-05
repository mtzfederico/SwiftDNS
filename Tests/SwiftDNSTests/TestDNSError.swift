//
//  TestDNSError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 

import Testing
@testable import SwiftDNS

struct TestDNSError {

    @Test func testDNSError_Equatable() async throws {
        #expect(DNSError.invalidData == DNSError.invalidData)
        #expect(DNSError.invalidData != DNSError.unknownState(nil))
        #expect(DNSError.invalidData != DNSError.unknownState(.preparing))
        #expect(DNSError.invalidData != DNSError.noDataReceived)
        #expect(DNSError.invalidData != DNSError.outOfBounds)
        #expect(DNSError.invalidData != DNSError.connectionIsNil)
        #expect(DNSError.invalidData != DNSError.invalidServerAddress)
        #expect(DNSError.invalidData != DNSError.connectionFailed(DNSError.connectionIsNil))
        #expect(DNSError.invalidData != DNSError.parsingError(nil))
        #expect(DNSError.invalidData != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.connectionIsNil != DNSError.invalidData)
        #expect(DNSError.connectionIsNil != DNSError.unknownState(nil))
        #expect(DNSError.connectionIsNil != DNSError.unknownState(.preparing))
        #expect(DNSError.connectionIsNil != DNSError.invalidServerAddress)
        #expect(DNSError.connectionIsNil != DNSError.noDataReceived)
        #expect(DNSError.connectionIsNil != DNSError.outOfBounds)
        #expect(DNSError.connectionIsNil == DNSError.connectionIsNil)
        #expect(DNSError.connectionIsNil != DNSError.invalidServerAddress)
        #expect(DNSError.connectionIsNil != DNSError.connectionFailed(DNSError.outOfBounds))
        #expect(DNSError.connectionIsNil != DNSError.parsingError(nil))
        #expect(DNSError.connectionIsNil != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.invalidServerAddress != DNSError.invalidData)
        #expect(DNSError.invalidServerAddress != DNSError.unknownState(nil))
        #expect(DNSError.invalidServerAddress != DNSError.unknownState(.preparing))
        #expect(DNSError.invalidServerAddress != DNSError.noDataReceived)
        #expect(DNSError.invalidServerAddress != DNSError.noDataReceived)
        #expect(DNSError.invalidServerAddress != DNSError.outOfBounds)
        #expect(DNSError.invalidServerAddress != DNSError.connectionIsNil)
        #expect(DNSError.invalidServerAddress == DNSError.invalidServerAddress)
        #expect(DNSError.invalidServerAddress != DNSError.connectionFailed(DNSError.noDataReceived))
        #expect(DNSError.invalidServerAddress != DNSError.parsingError(nil))
        #expect(DNSError.invalidServerAddress != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.parsingError(nil) != DNSError.invalidData)
        #expect(DNSError.parsingError(nil) != DNSError.unknownState(nil))
        #expect(DNSError.parsingError(nil) != DNSError.unknownState(.preparing))
        #expect(DNSError.parsingError(DNSError.invalidData) != DNSError.unknownState(.preparing))
        #expect(DNSError.parsingError(nil) != DNSError.invalidServerAddress)
        #expect(DNSError.parsingError(nil) != DNSError.noDataReceived)
        #expect(DNSError.parsingError(nil) != DNSError.outOfBounds)
        #expect(DNSError.parsingError(nil) != DNSError.connectionIsNil)
        #expect(DNSError.parsingError(nil) != DNSError.invalidServerAddress)
        #expect(DNSError.parsingError(nil) != DNSError.connectionFailed(DNSError.connectionIsNil))
        #expect(DNSError.parsingError(nil) == DNSError.parsingError(nil))
        #expect(DNSError.parsingError(DNSError.noDataReceived) == DNSError.parsingError(DNSError.noDataReceived))
        #expect(DNSError.parsingError(nil) != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.outOfBounds != DNSError.invalidData)
        #expect(DNSError.outOfBounds != DNSError.unknownState(nil))
        #expect(DNSError.outOfBounds != DNSError.unknownState(.preparing))
        #expect(DNSError.outOfBounds != DNSError.noDataReceived)
        #expect(DNSError.outOfBounds == DNSError.outOfBounds)
        #expect(DNSError.outOfBounds != DNSError.connectionIsNil)
        #expect(DNSError.outOfBounds != DNSError.invalidServerAddress)
        #expect(DNSError.outOfBounds != DNSError.connectionFailed(DNSError.invalidServerAddress))
        #expect(DNSError.outOfBounds != DNSError.parsingError(nil))
        #expect(DNSError.outOfBounds != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.unknownState(nil) != DNSError.invalidData)
        #expect(DNSError.unknownState(nil) == DNSError.unknownState(nil))
        #expect(DNSError.unknownState(.preparing) == DNSError.unknownState(.preparing))
        #expect(DNSError.unknownState(nil) != DNSError.invalidServerAddress)
        #expect(DNSError.unknownState(nil) != DNSError.noDataReceived)
        #expect(DNSError.unknownState(nil) != DNSError.outOfBounds)
        #expect(DNSError.unknownState(nil) != DNSError.connectionIsNil)
        #expect(DNSError.unknownState(nil) != DNSError.invalidServerAddress)
        #expect(DNSError.unknownState(nil) != DNSError.connectionFailed(DNSError.connectionIsNil))
        #expect(DNSError.unknownState(nil) != DNSError.parsingError(nil))
        #expect(DNSError.unknownState(nil) != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.invalidData)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.unknownState(nil))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.unknownState(.preparing))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.noDataReceived)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.outOfBounds)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.connectionIsNil)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.invalidServerAddress)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.connectionFailed(DNSError.outOfBounds))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) == DNSError.connectionFailed(DNSError.noDataReceived))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.parsingError(nil))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.parsingError(DNSError.noDataReceived))
        
        #expect(DNSError.noDataReceived != DNSError.invalidData)
        #expect(DNSError.noDataReceived != DNSError.unknownState(nil))
        #expect(DNSError.noDataReceived != DNSError.unknownState(.preparing))
        #expect(DNSError.noDataReceived == DNSError.noDataReceived)
        #expect(DNSError.noDataReceived != DNSError.outOfBounds)
        #expect(DNSError.noDataReceived != DNSError.connectionIsNil)
        #expect(DNSError.noDataReceived != DNSError.invalidServerAddress)
        #expect(DNSError.noDataReceived != DNSError.connectionFailed(DNSError.invalidData))
        #expect(DNSError.noDataReceived != DNSError.parsingError(nil))
        #expect(DNSError.noDataReceived != DNSError.parsingError(DNSError.noDataReceived))
        
        // print(DNSError.connectionFailed(DNSError.outOfBounds).localizedDescription)
        // print(DNSError.unknownState(.preparing).localizedDescription)
        // print(DNSError.parsingError(DNSError.IDMismatch).localizedDescription)
    }
}

