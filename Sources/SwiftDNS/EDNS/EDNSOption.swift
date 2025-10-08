//
//  EDNSOption.swift
//  SwiftDNS
//
//  Created by FedeMtz on 2025-10-04
// 

import Foundation

public struct EDNSOption: Sendable, Equatable {
    public let code: EDNSOptionCode
    public let values: [String: String]
    
    init(code: EDNSOptionCode, values: [String: String]) { // SendableLosslessStringConvertible
        self.code = code
        self.values = values
    }
    
    /// Decodes an EDNS Option and returns it as a string
    /// - Parameters:
    ///   - data: The data representing the EDNS Option
    ///   - offset: The position where the data is read at
    public init(data: Data, offset: inout Int) throws {
        // Read OPTION-CODE
        let rawOptionCode = data.subdata(in: offset..<offset+2).withUnsafeBytes {
            $0.load(as: UInt16.self).bigEndian
        }
        offset += 2
        
        // Read OPTION-LENGTH
        let optionLength = data.subdata(in: offset..<offset+2).withUnsafeBytes {
            $0.load(as: UInt16.self).bigEndian
        }
        offset += 2
        
        // Check that the data is within the length
        guard offset + Int(optionLength) <= data.count else {
            throw DNSError.parsingError(DNSError.invalidData("edns option length out of bounds"))
        }
        
        // Read OPTION-DATA
        let optionData = data.subdata(in: offset..<offset+Int(optionLength))
        offset += Int(optionLength)
        
        guard let optionCode = EDNSOptionCode(rawValue: rawOptionCode) else {
            throw DNSError.invalidData("invalid EDNS option code: '\(rawOptionCode)'")
        }
        
        self.code = optionCode
        
        switch code {
        case .COOKIE:
            // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2
            if optionData.count < 8 {
                throw DNSError.invalidData("Invalid EDNS Cookie. Data too short")
            }
            
            let clientCookie = optionData.subdata(in: 0..<8).hexEncodedString() // .map { String(format: "%02hhx", $0) }.joined()
            let serverCookie = optionData.count > 8 ? optionData.subdata(in: 8..<optionData.count).hexEncodedString() /* .map { String(format: "%02x", $0) }.joined()*/ : "None"
            
            self.values = ["Client": clientCookie, "Server": serverCookie]
        case .ClientSubnet:
            guard optionData.count >= 4 else { throw DNSError.invalidData("Invalid EDNS Client Subnet. Data too short") }
            print("[decodeEDNSOption]: ClientSubnet. data: \(optionData.hexEncodedString())")
            
            let family = UInt16(bigEndian: optionData.subdata(in: 0..<2).withUnsafeBytes { $0.load(as: UInt16.self) })
            let sourceMask = data[2]
            let scopeMask = data[3]
            
            let addressBytes = data.subdata(in: 4..<optionData.count)
            
            let ipString: String
            switch family {
            case 1:
                // IPv4
                // Adds missing octets set to zero to make sure that they are printed
                let paddedAddress = addressBytes + Data(repeating: 0, count: max(0, 4 - addressBytes.count))
                ipString = paddedAddress.map { String($0) }.joined(separator: ".")
                // ipString = addressBytes.prefix(4).map { String($0) }.joined(separator: ".")
            case 2:
                // IPv6
                // Adds missing hextets set to zero to make sure that they are printed
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
            
            self.values = ["Family": String(family), "SourceMask": String(sourceMask), "ScopeMask": String(scopeMask), "IP": ipString]
            return
        case .KeepAlive:
            #warning("needs testing")
            guard optionData.count == 2 else { throw DNSError.invalidData("Invalid EDNS KEEPALIVE. Bad length: \(optionData.count)") }
            
            let timeout = UInt16(bigEndian: optionData.withUnsafeBytes { $0.load(as: UInt16.self) })
            self.values = ["Timeout": timeout.description]
        case .Padding:
            #warning("needs testing")
            self.values = ["Padding": optionData.hexEncodedString()]
        case .ExtendedDNSError:
            guard optionLength >= 2 else { throw DNSError.invalidData("Invalid EDNS Extended Error. Bad length: \(optionLength)") }
            
            let code = UInt16(bigEndian: optionData.withUnsafeBytes { $0.load(as: UInt16.self) })
            guard let extendedError = EDNSExtendedError(rawValue: code) else {
                throw DNSError.invalidData("Invalid EDNS Extended Error. Failed to parse code: \(code)")
            }
            
            var values: [String: String] = ["Extended Error Code": extendedError.description]
            
            if optionLength > 2 {
                let extraText = String(data: optionData.subdata(in: Int(optionLength)-2..<optionData.count), encoding: .utf8)
                values["Extra Text"] = extraText
            }
            #warning("needs testing")
            self.values = values
        default:
            if let str = String(data: optionData, encoding: .utf8), str.isPrintable {
                self.values = ["Unknown": str]
                return
            }
            // fallback to hex representation
            self.values = ["Unknown": "0x\(optionData.hexEncodedString())"]
        }
    }
    
    public func toData() throws -> Data {
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
                  let rawScopeMask = values["SourceMask"], let scopeMask = UInt8(rawScopeMask),
                  let ipString = values["IP"]
            else {
                throw DNSError.invalidData("Invalid EDNS Client Subnet values")
            }
            
            optionData.append(contentsOf: withUnsafeBytes(of: family) { Data($0) })
            optionData.append(sourceMask)
            optionData.append(scopeMask)
            
            switch family {
            case 1:
                let octets = ipString.split(separator: ".").compactMap { UInt8($0) }
                guard octets.count == 4 else {
                    throw DNSError.parsingError(DNSError.invalidData("Invalid A record IP: \(ipString)"))
                }
                optionData.append(contentsOf: octets)
            case 2:
                var dst = in6_addr()
                let success = ipString.withCString { cstr in
                    inet_pton(AF_INET6, cstr, &dst)
                }
                
                guard success == 1 else {
                    throw DNSError.parsingError(DNSError.invalidData("Invalid IPv6 address: '\(ipString)'"))
                }
                
                // Convert in6_addr to Data (16 bytes)
                optionData.append(Data(bytes: &dst, count: MemoryLayout<in6_addr>.size))
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
    }
    
    var description: String {
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
