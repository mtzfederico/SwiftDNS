//
//  Data+Extension.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

extension Data {
    
    /// Initializes Data with a hex/base16 string.
    ///
    /// The string is case insensitive and whitespace is not allowed
    /// - Parameter hex: The hex encoded data as defined by [RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-8)
    init(hex: String) throws {
            var hex = hex
            var data = Data()

            guard hex.count % 2 == 0 else {
                throw DNSError.invalidData("Hex string must have an even number of characters.")
            }
        
            while !hex.isEmpty {
                let byteStr = String(hex.prefix(2))
                hex = String(hex.dropFirst(2))

                guard let byte = UInt8(byteStr, radix: 16) else {
                    throw DNSError.invalidData("Character is not base 16: '\(byteStr)'")
                }

                data.append(byte)
            }

            self = data
        }
    
    /// Returns the data as a hex-encoded string with no spaces and no prefix as defined by [RFC4648](https://datatracker.ietf.org/doc/html/rfc4648#section-8)
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
