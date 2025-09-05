//
//  DNSError.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation
import Network

/// The errors used by SwiftDNS
public enum DNSError: Error, Equatable, LocalizedError {
    /// No data was received from the server
    case noDataReceived
    /// The conenction failed
    case connectionFailed(Error)
    /// Unknown connection state
    case unknownState(NWConnection.State?)
    /// Reached outside of the bounds of the DNS data
    case outOfBounds
    /// A parsing error occurred when procesing the response
    case parsingError(Error?)
    /// The DNS server's address is invalid
    case invalidServerAddress
    /// The connection to the server is nil
    case connectionIsNil
    /// Received invalid data
    case invalidData
    /// The ID sent in the query is not the same as the one in the response
    case IDMismatch
    
    
    public var errorDescription: String? {
        switch self {
        case .noDataReceived:
            return NSLocalizedString("DNSError.noDataReceived", comment: "")
        case .connectionFailed(let error):
            return String(format: NSLocalizedString("DNSError.connectionFailed", comment: ""), error.localizedDescription)
        case .unknownState(let state):
            return String(format: NSLocalizedString("DNSError.unknownState", comment: ""), state.debugDescription)
        case .outOfBounds:
            return NSLocalizedString("DNSError.outOfBounds", comment: "")
        case .parsingError(let error):
            return String(format: NSLocalizedString("DNSError.parsingError", comment: ""), error?.localizedDescription ?? "<nil>")
        case .invalidServerAddress:
            return NSLocalizedString("DNSError.invalidServerAddress", comment: "")
        case .connectionIsNil:
            return NSLocalizedString("DNSError.connectionIsNil", comment: "")
        case .invalidData:
            return NSLocalizedString("DNSError.invalidData", comment: "")
        case .IDMismatch:
            return NSLocalizedString("DNSError.IDMismatch", comment: "")
        }
    }
    
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
        case (.noDataReceived, .noDataReceived), (.invalidData, .invalidData), (.IDMismatch, .IDMismatch):
            return true
        case (.invalidServerAddress, .invalidServerAddress), (.connectionIsNil, .connectionIsNil), (.outOfBounds, .outOfBounds):
            return true
        default:
            return false
        }
    }
}
