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
            // Exclude ASCII control characters (U+0000 through U+001F and U+007F)
            !(scalar.value >= 0x00 && scalar.value <= 0x1F) && scalar.value != 0x7F
        }
    }
}
