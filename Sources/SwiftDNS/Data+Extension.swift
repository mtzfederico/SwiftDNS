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
    
    /// Reads a UInt16 at the index as a Big Endian
    func readUInt16(at index: Int) throws -> UInt16 {
        guard index + 1 < self.count else {
            throw NSError(domain: "Data out of bounds", code: 2, userInfo: nil)
        }
        let high = UInt16(self[index]) << 8
        let low = UInt16(self[index + 1])
        return high | low
    }
}
