//
//  DNSError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation
import Network

/// The errors used by SwiftDNS
public enum DNSError: Error, Equatable {
    case noAnswer
    case noDataReceived
    case connectionFailed(Error)
    case unknownState(NWConnection.State?)
    case outOfBounds
    case parsingError(Error?)
    case invalidServerAddress
    case connectionIsNil
    case invalidData
    
    public static func ==(lhs: DNSError, rhs: DNSError) -> Bool {
        switch (lhs, rhs) {
        case (.connectionFailed(let lhsE), .connectionFailed(let rhsE)):
            return lhsE as NSError == rhsE as NSError
        case (.parsingError(let lhsE), .parsingError(let rhsE)):
            if let lhsE = lhsE as NSError?, let rhsE = rhsE as NSError? {
                return lhsE as NSError == rhsE as NSError
            } else {
                return lhsE == nil && rhsE == nil
            }
        case (.unknownState(let lhsE), .unknownState(let rhsE)):
            if let lhsE = lhsE, let rhsE = rhsE {
                return lhsE == rhsE
            } else {
                return lhsE == nil && rhsE == nil
            }
        case (.noAnswer, .noAnswer), (.noDataReceived, .noDataReceived), (.invalidData, .invalidData):
            return true
        case (.invalidServerAddress, .invalidServerAddress), (.connectionIsNil, .connectionIsNil), (.outOfBounds, .outOfBounds):
            return true
        default:
            return false
        }
    }
}
