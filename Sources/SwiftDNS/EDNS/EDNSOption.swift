//
//  EDNSOption.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-10-04
// 

import Foundation
import Network

public struct EDNSOption: Sendable, Equatable, CustomStringConvertible {
    public let code: EDNSOptionCode
    public let values: [String: String]
    
    /// Initislizes an EDNS Client Subnet Option
    /// - Parameters:
    ///   - family: The family of the IP Address. 1 for IPv4 and 2 for IPv6
    ///   - IP: The IP Address
    ///   - sourceMask: The subnet mask of the network
    ///   - scopeMask: The scope mask. This is only used in responses
    public init(family: Int, IP: String, sourceMask: Int, scopeMask: Int = 0) {
        self = EDNSOption(code: .ClientSubnet, values: ["Family": "\(family)", "SourceMask": "\(sourceMask)", "ScopeMask": "\(scopeMask)", "IP": "\(IP)"])
    }
    
    public init(code: EDNSOptionCode, values: [String: String]) {
        self.code = code
        self.values = values
    }
    
    /// Decodes an EDNS Option from Data
    /// - Parameters:
    ///   - data: The data representing the EDNS Option begining at the option code
    ///   - offset: The position where the data is read at
    public init(data: Data, offset: inout Int) throws {
        // Read OPTION-CODE
        // let rawOptionCode = data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        let rawOptionCode = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2
        
        // Read OPTION-LENGTH
        let optionLength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        // let optionLength = data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        offset += 2
        
        // Check that the data is within the length
        guard offset + Int(optionLength) <= data.count else {
            throw DNSError.parsingError(DNSError.invalidData("EDNS option length out of bounds"))
        }
        
        // Read OPTION-DATA
        let optionData = data.subdata(in: offset..<offset+Int(optionLength))
        // print("[decodeEDNSOption]: optionData: \(optionData.hexEncodedString())")
        
        // offset += Int(optionLength)
        
        guard let optionCode = EDNSOptionCode(rawValue: rawOptionCode) else {
            throw DNSError.invalidData("invalid EDNS option code: '\(rawOptionCode)'")
        }
        
        // print("[decodeEDNSOption]: rawOptionCode: \(rawOptionCode). optionCode: \(optionCode.description)")
        
        self.code = optionCode
        
        switch code {
        case .COOKIE:
            // https://datatracker.ietf.org/doc/html/rfc7873#section-4
            // The client cookie has a fixed length of 8 bytes and the server Cookie has a variable size of 8 to 32 bytes
            guard optionLength >= 8 && optionLength <= 40 else {
                throw DNSError.invalidData("Invalid EDNS Cookie. Bad length: \(optionLength)")
            }
            
            let clientCookie = optionData.subdata(in: 0..<8).hexEncodedString()
            let serverCookie = optionLength > 8 ? optionData.subdata(in: 8..<Int(optionLength)).hexEncodedString() : "None"
            offset += Int(optionLength)
            
            self.values = ["Client": clientCookie, "Server": serverCookie]
        case .ClientSubnet:
            guard optionLength >= 4 else {
                throw DNSError.invalidData("Invalid EDNS Client Subnet. Data too short: \(optionLength)")
            }
            
            let family = UInt16(bigEndian: optionData.subdata(in: 0..<2).withUnsafeBytes { $0.load(as: UInt16.self) })
            let sourceMask: UInt8 = optionData[2]
            let scopeMask: UInt8 = optionData[3]
            
            let addressBytes = optionData.subdata(in: 4..<optionData.count)
            
            let ipString: String
            switch family {
            case 1:
                // IPv4
                // Adds missing octets set to zero to make sure that they are printed
                guard addressBytes.count <= 4 else {
                    throw DNSError.invalidData("EDNS CLient Subnet IPv4 address too long: \(addressBytes.count) bytes")
                }
                
                let paddedAddress = addressBytes + Data(repeating: 0, count: max(0, 4 - addressBytes.count))
                ipString = paddedAddress.map { String($0) }.joined(separator: ".")
                // ipString = paddedAddress.prefix(4).map { String($0) }.joined(separator: ".")
                
            case 2:
                // IPv6
                // Adds missing hextets set to zero to make sure that they are printed
                guard addressBytes.count <= 16 else {
                    throw DNSError.invalidData("EDNS CLient Subnet IPv6 address too long: \(addressBytes.count) bytes")
                }
                
                let paddedAddress = addressBytes + Data(repeating: 0, count: max(0, 16 - addressBytes.count))
                
                var segments: [String] = []
                for i in stride(from: 0, to: paddedAddress.count, by: 2) {
                    let part = (UInt16(paddedAddress[i]) << 8) | UInt16(paddedAddress[i + 1])
                    segments.append(String(format: "%x", part))
                }
                
                ipString = segments.joined(separator: ":")
            default:
                ipString = "Failed to parse address. '\(addressBytes.hexEncodedString())'"
            }
            offset += Int(optionLength)
            self.values = ["Family": String(family), "SourceMask": String(sourceMask), "ScopeMask": String(scopeMask), "IP": ipString]
            return
        case .KeepAlive:
            guard optionLength == 2 else { throw DNSError.invalidData("Invalid EDNS KEEPALIVE. Bad length: \(optionLength)") }
            
            let timeout = UInt16(bigEndian: optionData.withUnsafeBytes { $0.load(as: UInt16.self) })
            offset += Int(optionLength)
            self.values = ["Timeout": timeout.description]
        case .Padding:
            offset += Int(optionLength)
            self.values = ["Padding": optionData.hexEncodedString()]
        case .ExtendedDNSError:
            guard optionLength >= 2 else { throw DNSError.invalidData("Invalid EDNS Extended Error. Bad length: \(optionLength)") }
            
            let code = UInt16(bigEndian: optionData.withUnsafeBytes { $0.load(as: UInt16.self) })
            let extendedError = EDNSExtendedError(code)
            offset += 2
            
            var values: [String: String] = ["Extended Error Code": extendedError.description]
            
            if optionLength > 2 {
                let textData = optionData.subdata(in: (offset-4)..<(offset + Int(optionLength-6)))
                offset += textData.count
                let extraText = String(data: textData, encoding: .utf8)
                values["Extra Text"] = extraText
            }
            self.values = values
        default:
            offset += Int(optionLength)
            if let str = String(data: optionData, encoding: .utf8), str.isPrintable {
                self.values = ["Unknown": str]
                return
            }
            // fallback to hex representation
            self.values = ["Unknown": "0x\(optionData.hexEncodedString())"]
        }
    }
    
    public func toData() throws -> Data {
        var finalData = Data()
        finalData.append(contentsOf: withUnsafeBytes(of: code.rawValue.bigEndian) { Data($0) })
        
        var optionData = Data()
        switch code {
        case .COOKIE:
            guard let clientCookie = values["Client"], let serverCookie = values["Server"] else {
                throw DNSError.invalidData("Invalid EDNS Client Subnet values")
            }
            
            optionData.append(try Data(hex: clientCookie))
            if serverCookie != "None" {
                optionData.append(try Data(hex: serverCookie))
            }
        case .ClientSubnet:
            guard let rawFamily = values["Family"], let family = UInt16(rawFamily),
                  let rawSourceMask = values["SourceMask"], let sourceMask = UInt8(rawSourceMask),
                  let rawScopeMask = values["ScopeMask"], let scopeMask = UInt8(rawScopeMask),
                  let ipString = values["IP"]
            else {
                throw DNSError.invalidData("Invalid EDNS Client Subnet values")
            }
            
            optionData.append(contentsOf: withUnsafeBytes(of: family.bigEndian) { Data($0) })
            optionData.append(sourceMask)
            optionData.append(scopeMask)
            
            switch family {
            case 1:
                let octets = ipString.split(separator: ".").compactMap { UInt8($0) }
                guard octets.count == 4 else {
                    throw DNSError.parsingError(DNSError.invalidData("Invalid A record IP: \(ipString)"))
                }
                
                // Calculate the number of bytes needed to hold the prefix bits and round up
                let byteCount = (Int(sourceMask) + 7) / 8
                // Only get the bytes in the prefix
                var prefix = octets.prefix(byteCount)
                
                // If the prefix doesn't end on a byte boundary, zero out the trailing bits in the last byte
                let remainingBits = sourceMask % 8
                if remainingBits != 0 {
                    let mask: UInt8 = 0xFF << (8 - remainingBits)
                    prefix[byteCount - 1] &= mask
                }
                
                optionData.append(contentsOf: prefix)
            case 2:
                guard let ipv6 = IPv6Address(ipString) else {
                    throw DNSError.parsingError(DNSError.invalidData("Invalid IPv6 address: \(ipString)"))
                }
                
                let rawBytes = ipv6.rawValue
                let bitCount = Int(sourceMask)
                // Calculate the number of bytes needed to hold the prefix bits and round up
                let byteCount = (bitCount + 7) / 8
                // Only get the bytes in the prefix
                var prefix = rawBytes.prefix(byteCount)
                
                // If the prefix doesn't end on a byte boundary, zero out the trailing bits in the last byte
                let remainingBits = bitCount % 8
                if remainingBits != 0 {
                    let mask: UInt8 = 0xFF << (8 - remainingBits)
                    prefix[byteCount - 1] &= mask
                }
                
                optionData.append(contentsOf: prefix)
            default:
                throw DNSError.invalidData("Unsupported IP family for EDNS Client Subnet: \(family)")
            }
        case .KeepAlive:
            guard let rawTimeout = values["Timeout"], let timeout = UInt16(rawTimeout) else {
                throw DNSError.invalidData("Invalid EDNS KeepAlive timeout")
            }
            
            optionData.append(contentsOf: withUnsafeBytes(of: timeout.bigEndian) { Data($0) })
        case .Padding:
            guard let padding = values["Padding"] else {
                throw DNSError.invalidData("Invalid EDNS padding")
            }
            
            optionData.append(try Data(hex: padding))
        case .ExtendedDNSError:
            guard let rawCode = values["Extended Error Code"], let code = EDNSExtendedError(rawCode) else {
                throw DNSError.invalidData("Invalid EDNS Client Subnet values")
            }
            
            optionData.append(contentsOf: withUnsafeBytes(of: code.rawValue.bigEndian) { Data($0) })
            
            if let extraText = values["Extra Text"] {
                optionData.append(contentsOf: extraText.utf8)
            }
        default:
            guard let unknownData = values["Unknown"] else {
                throw DNSError.invalidData("Unknown Client Subnet values")
            }
            
            if unknownData.hasPrefix("0x") {
                optionData.append(try Data(hex: String(unknownData.dropFirst(2))))
            } else {
                optionData.append(contentsOf: unknownData.utf8)
            }
        }
        
        finalData.append(contentsOf: withUnsafeBytes(of: UInt16(optionData.count).bigEndian) { Data($0) })
        finalData.append(contentsOf: optionData)
        return finalData
    }
    
    /// A description of the EDNS Option
    ///
    ///Format:
    /// EDNS Option Code: key=value
    public var description: String {
        var description: String = "\(code.description): "
        
        let count = values.count
        var i = 0
        for value in values {
            description += "\(value.key)=\(value.value)\(i == count ? "" : ", ")"
            i += 1
        }
        return description
    }
    
    public static func ==(lhs: EDNSOption, rhs: EDNSOption) -> Bool {
        return lhs.code == rhs.code && lhs.values == rhs.values
    }
}
