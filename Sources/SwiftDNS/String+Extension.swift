//
//  String+Extension.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

extension String {
    /// Returns true if it doesn't contain any control characters and should be safe to print
    var isPrintable: Bool {
        return self.unicodeScalars.allSatisfy { scalar in
            // Exclude ASCII control characters (U+0000 through U+001F and U+007F) U+0020 is space
            !(scalar.value >= 0x00 && scalar.value <= 0x1F) && scalar.value != 0x7F
        }
    }
    
    /// Returns true if the string only contains valid dns characters for a hostname.
    ///
    /// Allowed characters: hyphen (-), period (.), underscore (_), numbers 0 to 9, and letters a to z lowercased and capitalized.
    var isDNSSafe: Bool {
        return self.unicodeScalars.allSatisfy { scalar in
            
            // hypen (-): 2D
            // period (.): 2E
            // underscore (_): 5F // Can be seen in srv record queries
            // 0 to 9: 30 to 39
            // A to Z: 41 to 5A
            // a to z: 61 to 7A
            
            scalar.value == 0x2D || scalar.value == 0x2E || scalar.value == 0x5F || (scalar.value >= 0x30 && scalar.value <= 0x39) || (scalar.value >= 0x41 && scalar.value <= 0x5A) || (scalar.value >= 0x61 && scalar.value <= 0x7A)
        }
    }
}
