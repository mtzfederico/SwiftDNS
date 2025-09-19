//
//  TestStringExtension.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-09-11
// 

import Testing
@testable import SwiftDNS

struct TestStringExtension {

    @Test func testIsPrintable() async throws {
        let items: [String: Bool] = [
            "": true,
            "google.com": true,
            "méxico.mx": true,
            "niños.com": true,
            "fußball.de": true,
            "xn--fuball-cta.de": true,
            "example.com\0": false,
            "example.com\t": false,
            "example.com\n": false,
            "example.com\r": false,
            
            "some string\u{01}": false,
            "some string\u{02}": false,
            "some string\u{03}": false,
            "some string\u{04}": false,
            "some string\u{05}": false,
            "some string\u{06}": false,
            "some string\u{07}": false,
            "some string\u{08}": false,
            "some string\u{0A}": false,
            "some string\u{0B}": false,
            "some string\u{0C}": false,
            "some string\u{0D}": false,
            "some string\u{0E}": false,
            "some string\u{0F}": false,
            
            "some string\u{11}": false,
            "some string\u{12}": false,
            "some string\u{13}": false,
            "some string\u{14}": false,
            "some string\u{15}": false,
            "some string\u{16}": false,
            "some string\u{17}": false,
            "some string\u{18}": false,
            "some string\u{19}": false,
            "some string\u{1A}": false,
            "some string\u{1B}": false,
            "some string\u{1C}": false,
            "some string\u{1D}": false,
            "some string\u{1E}": false,
            "some string\u{1F}": false,
            
            "some string\u{20}": true,
            "some string\u{7f}": false,
        ]
        
        for item in items {
            #expect(item.key.isPrintable == item.value)
        }
    }
    
    @Test func testIsDNSSafe() async throws {
        let items: [String: Bool] = [
            "": true,
            " ": false,
            "google.com": true,
            "localhost": true,
            "as209245.net": true,
            "0123456789.invalid": true,
            "3.2.168.192.in-addr.arpa.": true,
            "e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.0.0.0.2.6.2.ip6.arpa": true,
            "https://example.com": false,
            "example.com/index.html": false,
            
            "méxico.mx": false,
            "xn--mxico-bsa.mx": true,
            
            "niños.com": false,
            "xn--nios-hqa.com": true,
            
            "fußball.de": false,
            "xn--fuball-cta.de": true,
            
            "δοκιμή.com": false,
            "xn--jxalpdlp.com": true,
            
            "example.рф": false,
            "example.xn--p1ai": true,
            
            "😀.com": false,
            "xn--e28h.com": true,
            
            "_jabber._tcp.gmail.com": true,
            "_sip._udp.apnic.net": true,
            
            "a*b.invalid": false,
            "a*b": false,
            "a&b": false,
            "(a)b)": false,
            "#a": false,
            "$b": false,
            "%c": false,
            "&d": false,
            "*e": false,
            "+f": false,
            "-g": true,
            "=h": false,
            ">i": false,
            "@j": false,
            "^k": false,
            
            "example.com\0": false,
            "example.com\t": false,
            "example.com\n": false,
            "example.com\nanother line": false,
            "example.com\r": false,
            
            "some string\u{01}": false,
            "some string\u{02}": false,
            "some string\u{03}": false,
            "some string\u{04}": false,
            "some string\u{05}": false,
            "some string\u{06}": false,
            "some string\u{07}": false,
            "some string\u{08}": false,
            "some string\u{0A}": false,
            "some string\u{0B}": false,
            "some string\u{0C}": false,
            "some string\u{0D}": false,
            "some string\u{0E}": false,
            "some string\u{0F}": false,
            
            "some string\u{11}": false,
            "some string\u{12}": false,
            "some string\u{13}": false,
            "some string\u{14}": false,
            "some string\u{15}": false,
            "some string\u{16}": false,
            "some string\u{17}": false,
            "some string\u{18}": false,
            "some string\u{19}": false,
            "some string\u{1A}": false,
            "some string\u{1B}": false,
            "some string\u{1C}": false,
            "some string\u{1D}": false,
            "some string\u{1E}": false,
            "some string\u{1F}": false,
            
            "some string": false,
            "some string\u{20}": false,
            "some string\u{7f}": false,
        ]
        
        for item in items {
            let isDNSSafe = item.key.isDNSSafe
            if isDNSSafe != item.value {
                print("'\(item.key)' got \(isDNSSafe). Should be \(item.value)")
            }
            #expect(isDNSSafe == item.value)
        }
    }
}
