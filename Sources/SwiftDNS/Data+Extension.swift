//
//  Data+Extension.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

extension Data {
    
    /// Returns the data as a hex-encoded string
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    /// Reads a UInt16 as Big Endian
    /// - Parameter index: The index to read the UInt16 at. Note: index + 1 should should be less than the lengtth of the data.
    /// - Returns: The UInt16 read.
    func readUInt16(at index: Int) throws -> UInt16 {
        guard index + 1 < self.count else {
            throw DNSError.invalidData("Data out of bounds")
        }
        let high = UInt16(self[index]) << 8
        let low = UInt16(self[index + 1])
        return high | low
    }
}
