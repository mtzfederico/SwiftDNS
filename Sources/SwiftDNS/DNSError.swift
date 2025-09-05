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
            return NSLocalizedString("DNSError.noDataReceived", bundle: .module, comment: "")
        case .connectionFailed(let error):
            let errorDesc = error.localizedDescription
            let format = NSLocalizedString("DNSError.connectionFailed %@", bundle: .module, comment: "")
            return String(format: format, errorDesc)
        case .unknownState(let state):
            let stateDesc = state.debugDescription
            let format = NSLocalizedString("DNSError.unknownState %@", bundle: .module, comment: "")
            return String.localizedStringWithFormat(format, stateDesc)
        case .outOfBounds:
            return NSLocalizedString("DNSError.outOfBounds", bundle: .module, comment: "")
        case .parsingError(let error):
            let errorDesc = error?.localizedDescription ?? "<nil>"
            let format = NSLocalizedString("DNSError.parsingError %@", bundle: .module, comment: "")
            return String.localizedStringWithFormat(format, errorDesc)
        case .invalidServerAddress:
            return NSLocalizedString("DNSError.invalidServerAddress", bundle: .module, comment: "")
        case .connectionIsNil:
            return NSLocalizedString("DNSError.connectionIsNil", bundle: .module, comment: "")
        case .invalidData:
            return NSLocalizedString("DNSError.invalidData", bundle: .module, comment: "")
        case .IDMismatch:
            return NSLocalizedString("DNSError.IDMismatch", bundle: .module, comment: "")
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
