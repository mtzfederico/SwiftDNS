//
//  TestDNSError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-20
// 

import Testing
@testable import SwiftDNS

struct TestDNSError {
    
    /// Verifies that two errors with the same associated values are equal.
    /// Covers every case's equality exactly once.
    @Test func testSameValues() {
        #expect(DNSError.invalidData("Out of bounds") == DNSError.invalidData("Out of bounds"))
        #expect(DNSError.unknownState(.preparing) == DNSError.unknownState(.preparing))
        #expect(DNSError.unknownState(nil) == DNSError.unknownState(nil))
        #expect(DNSError.noDataReceived == DNSError.noDataReceived)
        #expect(DNSError.IDMismatch(got: 0xab, expected: 0xba) == DNSError.IDMismatch(got: 0xab, expected: 0xba))
        #expect(DNSError.invalidDomainName == DNSError.invalidDomainName)
        #expect(DNSError.connectionIsNil == DNSError.connectionIsNil)
        #expect(DNSError.invalidServerAddress == DNSError.invalidServerAddress)
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) == DNSError.connectionFailed(DNSError.noDataReceived))
        #expect(DNSError.connectionClosed == DNSError.connectionClosed)
        #expect(DNSError.parsingError(nil) == DNSError.parsingError(nil))
        #expect(DNSError.parsingError(DNSError.noDataReceived) == DNSError.parsingError(DNSError.noDataReceived))
        #expect(DNSError.connectionTypeMismatch == DNSError.connectionTypeMismatch)
        #expect(DNSError.responseTruncated == DNSError.responseTruncated)
        #expect(DNSError.namePointerLoop(at: 0, to: 2) == DNSError.namePointerLoop(at: 0, to: 2))
    }
    
    /// Verifies that errors with different associated values of the same type are not equal.
    @Test func testDifferentAssociatedValues() {
        #expect(DNSError.invalidData("") != DNSError.invalidData("Out of bounds"))
        #expect(DNSError.unknownState(nil) != DNSError.unknownState(.preparing))
        #expect(DNSError.IDMismatch(got: 0, expected: 0xbb) != DNSError.IDMismatch(got: 0, expected: 0xaa))
        #expect(DNSError.IDMismatch(got: 0xaa, expected: 0) != DNSError.IDMismatch(got: 0xbb, expected: 0))
        #expect(DNSError.connectionFailed(DNSError.noDataReceived) != DNSError.connectionFailed(DNSError.invalidData("Out of bounds")))
        #expect(DNSError.parsingError(nil) != DNSError.parsingError(DNSError.noDataReceived))
        #expect(DNSError.namePointerLoop(at: 0, to: 2) != DNSError.namePointerLoop(at: 2, to: 4))
    }
    
    /// Verifies that every pair error cases is unequal.
    /// Each unordered pair is checked exactly once.
    @Test func testDifferentCases() {
        // Use one representative per case type to keep cross-case checks unambiguous
        let invalidData = DNSError.invalidData("")
        let unknownState = DNSError.unknownState(nil)
        let noDataReceived = DNSError.noDataReceived
        let idMismatch = DNSError.IDMismatch(got: 0, expected: 0)
        let invalidDomainName = DNSError.invalidDomainName
        let connectionIsNil = DNSError.connectionIsNil
        let invalidServerAddr = DNSError.invalidServerAddress
        let connectionFailed = DNSError.connectionFailed(DNSError.noDataReceived)
        let connectionClosed = DNSError.connectionClosed
        let parsingError = DNSError.parsingError(nil)
        let connTypeMismatch = DNSError.connectionTypeMismatch
        let responseTruncated = DNSError.responseTruncated
        let namePointerLoop = DNSError.namePointerLoop(at: 0, to: 2)
        
        // When adding a new error, add one #expect with the new one to each block
        
        #expect(invalidData != unknownState)
        #expect(invalidData != noDataReceived)
        #expect(invalidData != idMismatch)
        #expect(invalidData != invalidDomainName)
        #expect(invalidData != connectionIsNil)
        #expect(invalidData != invalidServerAddr)
        #expect(invalidData != connectionFailed)
        #expect(invalidData != parsingError)
        #expect(invalidData != connTypeMismatch)
        #expect(invalidData != responseTruncated)
        #expect(invalidData != namePointerLoop)
        #expect(invalidData != connectionClosed)
        // #expect(invalidData != newError)
        
        #expect(unknownState != noDataReceived)
        #expect(unknownState != idMismatch)
        #expect(unknownState != invalidDomainName)
        #expect(unknownState != connectionIsNil)
        #expect(unknownState != invalidServerAddr)
        #expect(unknownState != connectionFailed)
        #expect(unknownState != parsingError)
        #expect(unknownState != connTypeMismatch)
        #expect(unknownState != responseTruncated)
        #expect(unknownState != namePointerLoop)
        #expect(unknownState != connectionClosed)
        
        #expect(noDataReceived != idMismatch)
        #expect(noDataReceived != invalidDomainName)
        #expect(noDataReceived != connectionIsNil)
        #expect(noDataReceived != invalidServerAddr)
        #expect(noDataReceived != connectionFailed)
        #expect(noDataReceived != parsingError)
        #expect(noDataReceived != connTypeMismatch)
        #expect(noDataReceived != responseTruncated)
        #expect(noDataReceived != namePointerLoop)
        #expect(noDataReceived != connectionClosed)
        
        #expect(idMismatch != invalidDomainName)
        #expect(idMismatch != connectionIsNil)
        #expect(idMismatch != invalidServerAddr)
        #expect(idMismatch != connectionFailed)
        #expect(idMismatch != parsingError)
        #expect(idMismatch != connTypeMismatch)
        #expect(idMismatch != responseTruncated)
        #expect(idMismatch != namePointerLoop)
        #expect(idMismatch != connectionClosed)
        
        #expect(invalidDomainName != connectionIsNil)
        #expect(invalidDomainName != invalidServerAddr)
        #expect(invalidDomainName != connectionFailed)
        #expect(invalidDomainName != parsingError)
        #expect(invalidDomainName != connTypeMismatch)
        #expect(invalidDomainName != responseTruncated)
        #expect(invalidDomainName != namePointerLoop)
        #expect(invalidDomainName != connectionClosed)
        
        #expect(connectionIsNil != invalidServerAddr)
        #expect(connectionIsNil != connectionFailed)
        #expect(connectionIsNil != parsingError)
        #expect(connectionIsNil != connTypeMismatch)
        #expect(connectionIsNil != responseTruncated)
        #expect(connectionIsNil != namePointerLoop)
        #expect(connectionIsNil != connectionClosed)
        
        #expect(invalidServerAddr != connectionFailed)
        #expect(invalidServerAddr != parsingError)
        #expect(invalidServerAddr != connTypeMismatch)
        #expect(invalidServerAddr != responseTruncated)
        #expect(invalidServerAddr != namePointerLoop)
        #expect(invalidServerAddr != connectionClosed)
        
        #expect(connectionFailed != parsingError)
        #expect(connectionFailed != connTypeMismatch)
        #expect(connectionFailed != responseTruncated)
        #expect(connectionFailed != namePointerLoop)
        #expect(connectionFailed != connectionClosed)
        
        #expect(parsingError != connTypeMismatch)
        #expect(parsingError != responseTruncated)
        #expect(parsingError != namePointerLoop)
        #expect(parsingError != connectionClosed)
        
        #expect(connTypeMismatch != responseTruncated)
        #expect(connTypeMismatch != namePointerLoop)
        #expect(connTypeMismatch != connectionClosed)
        
        #expect(responseTruncated != namePointerLoop)
        #expect(responseTruncated != connectionClosed)
    }
}

