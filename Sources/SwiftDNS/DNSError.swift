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
    /// A parsing error occurred when procesing the response
    case parsingError(Error?)
    /// The DNS server's address is invalid
    case invalidServerAddress
    /// The connection to the server is nil
    case connectionIsNil
    /// Received invalid data
    case invalidData(String)
    /// The ID sent in the query is not the same as the one in the response
    case IDMismatch(got: UInt16, expected: UInt16)
    /// The domain name used in the query is invalid
    case invalidDomainName
    /// The connection type attempted doesn't match the one of the DNSClient
    case connectionTypeMismatch
    
    
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
        case .parsingError(let error):
            let errorDesc = error?.localizedDescription ?? "<nil>"
            let format = NSLocalizedString("DNSError.parsingError %@", bundle: .module, comment: "")
            return String.localizedStringWithFormat(format, errorDesc)
        case .invalidServerAddress:
            return NSLocalizedString("DNSError.invalidServerAddress", bundle: .module, comment: "")
        case .connectionIsNil:
            return NSLocalizedString("DNSError.connectionIsNil", bundle: .module, comment: "")
        case .invalidData(let value):
            let format = NSLocalizedString("DNSError.invalidData %@", bundle: .module, comment: "")
            return String(format: format, value)
        case .IDMismatch(let got, let expected):
            #warning("this needs to be changed for UInt16")
            let format = NSLocalizedString("DNSError.IDMismatch %u %u", bundle: .module, comment: "")
            return String(format: format, got, expected)
        case .invalidDomainName:
            return NSLocalizedString("DNSError.invalidDomainName", bundle: .module, comment: "")
        case .connectionTypeMismatch:
            return NSLocalizedString("DNSError.connectionTypeMismatch", bundle: .module, comment: "")
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
        case (.invalidData(let lhsValue), .invalidData(let rhsValue)):
            return lhsValue == rhsValue
        case (.IDMismatch(let lhsGot, let lhsExpected), .IDMismatch(let rhsGot, let rhsExpected)):
            return lhsGot == rhsGot && lhsExpected == rhsExpected
        case (.noDataReceived, .noDataReceived), (.invalidDomainName, .invalidDomainName), (.connectionTypeMismatch, .connectionTypeMismatch):
            return true
        case (.invalidServerAddress, .invalidServerAddress), (.connectionIsNil, .connectionIsNil):
            return true
        default:
            return false
        }
    }
}
