//
//  DNSError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

enum DNSError: Error, Equatable {
    case noAnswer
    case noDataReceived
    case connectionFailed(Error)
    case unknownState
    case outOfBounds
    // case invalidResponse
    case parsingError(Error?)
    case invalidServerAddress
    case connectionIsNil
    case invalidData
    
    static func ==(lhs: DNSError, rhs: DNSError) -> Bool {
        switch (lhs, rhs) {
        case (.connectionFailed(let lhsE), .connectionFailed(let rhsE)):
            return lhsE as NSError == rhsE as NSError
        case (.parsingError(let lhsE), .parsingError(let rhsE)):
            if let lhsE = lhsE as NSError?, let rhsE = rhsE as NSError? {
                return lhsE as NSError == rhsE as NSError
            } else {
                return lhsE == nil && rhsE == nil
            }
        case (.noAnswer, .noAnswer), (.noDataReceived, .noDataReceived), (.unknownState, .unknownState), (.invalidData, .invalidData):
            return true
        case (.invalidServerAddress, .invalidServerAddress), (.connectionIsNil, .connectionIsNil), (.outOfBounds, .outOfBounds):
            return true
        default:
            return false
        }
    }
}
