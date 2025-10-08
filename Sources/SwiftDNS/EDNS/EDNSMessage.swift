//
//  EDNSMessage.swift
//  SwiftDNS
//
//  Created by FedeMtz on 2025-10-02
// 

import Foundation

/// The EDNS data as defined in [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)
public struct EDNSMessage: Sendable {
    /// The max UDP payload size. The default value is 1232 as recommended by [DNS Flag Day 2020](https://www.dnsflagday.net/2020/)
    public let udpPayloadSize: UInt16
    public let extendedRcode: UInt8
    public let version: UInt8
    public let zField: UInt16
    /// Used to indicate to the server to send DNSSEC Resource Records as defined in [RFC 3225](https://www.rfc-editor.org/rfc/rfc3225)
    public let doBit: Bool
    /// The EDNS options
    public let options: [EDNSOption]
    
    init(extendedRcode: UInt8, version: UInt8, zField: UInt16, doBit: Bool, options: [EDNSOption], udpPayloadSize: UInt16 = 1232) {
        self.udpPayloadSize = udpPayloadSize
        self.extendedRcode = extendedRcode
        self.version = version
        self.zField = zField
        self.doBit = doBit
        self.options = options
    }
    
    public init(data: Data, offset: inout Int) throws {
        // let (domainName, domainLength) = try DNSClient.parseDomainName(data: data, offset: offset)
        offset += 0 // domainLength
        
        // if domainName != "" { }
        
        // Read TYPE, CLASS, TTL, RDLENGTH
        guard offset + 10 <= data.count else {
            offset += 10
            // print("[decodeResourceRecord] Offset over bounds. offset: \(offset), data.count: \(data.count)")
            throw DNSError.invalidData("Offset (\(offset)) over bounds (\(data.count)) for TYPE, CLASS, TTL, and RDLENGTH")
        }
        
        // let rawType = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        // type must be == 41
        
        offset += 2 // type
        
        udpPayloadSize = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2 // udpPayloadSize (the class)
        
        let ttl = UInt32(bigEndian: data.subdata(in: offset..<offset+4).withUnsafeBytes { $0.load(as: UInt32.self) })
        offset += 4 // ttl
        
        let rdlength = UInt16(bigEndian: data.subdata(in: offset..<offset+2).withUnsafeBytes { $0.load(as: UInt16.self) })
        offset += 2 // rdLength
        
        guard offset + Int(rdlength) <= data.count else {
            offset += Int(rdlength)
            throw DNSError.parsingError(DNSError.invalidData("Failed to parse OPT record: offset (\(offset)) out of bounds (\(data.count))"))
        }

        let start = offset
        // https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2
        //
        // +------------+--------------+------------------------------+
        // | Field Name | Field Type   | Description                  |
        // +------------+--------------+------------------------------+
        // | NAME       | domain name  | MUST be 0 (root domain)      |
        // | TYPE       | u_int16_t    | OPT (41)                     |
        // | CLASS      | u_int16_t    | requestor's UDP payload size |
        // | TTL        | u_int32_t    | extended RCODE and flags     |
        // | RDLEN      | u_int16_t    | length of all RDATA          |
        // | RDATA      | octet stream | {attribute,value} pairs      |
        // +------------+--------------+------------------------------+
        //
        
        // TTL Format:
        //
        //           +0 (MSB)                            +1 (LSB)
        // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        //  0: |         EXTENDED-RCODE        |            VERSION        |
        // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        // 2: | DO|                           Z                            |
        // +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        //
        
        /// Forms the upper 8 bits of extended 12-bit RCODE (together with the 4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0 indicates that an unextended RCODE is in use (values 0 through 15).
        extendedRcode = UInt8((ttl & 0xFF00_0000) >> 24)
        /// Indicates the implementation level of the setter.  Full conformance with this specification is indicated by version '0'.
        ///
        /// Requestors are encouraged to set this to the lowest implemented level capable of expressing a transaction, to minimise the responder and network load of discovering the greatest common implementation level between requestor and responder.
        /// A requestor's version numbering strategy MAY ideally be a run-time configuration option.
        /// If a responder does not implement the VERSION level of the request, then it MUST respond with RCODE=BADVERS.
        /// All responses MUST be limited in format to the VERSION level of the request, but the VERSION of each response SHOULD be the highest implementation level of the responder.  In this way, a requestor will learn the implementation level of a responder as a side effect of every response, including error responses and including RCODE=BADVERS.
        version = UInt8((ttl & 0x00FF_0000) >> 16)
        /// Set to zero by senders and ignored by receivers, unless modified in a subsequent specification.
        zField = UInt16(ttl & 0x0000_FFFF)

        /// DNSSEC OK bit as defined by [RFC3225](https://www.rfc-editor.org/rfc/rfc3225).
        doBit = (zField & 0x8000) != 0
        
        var options: [EDNSOption] = []
        
        let end = start + Int(rdlength)
        while offset + 4 <= end {
            options.append(try EDNSOption(data: data, offset: &offset))
        }
        
        self.options = options
    }
    
    public func toData() throws -> Data {
        var data = try QuestionSection.encodeDomainName(name: "")
        
        let qtype: UInt16 = 41
        data.append(contentsOf: withUnsafeBytes(of: qtype.bigEndian) { Data($0) })
        data.append(contentsOf: withUnsafeBytes(of: udpPayloadSize.bigEndian) { Data($0) })
        
        var zField: UInt16 = self.zField
        
        // Set or clear the DO bit (bit 15)
        if doBit {
            // Set DO bit (bit 15) to 1. 0x8000 == 10000000 00000000
            zField = zField | 0x8000

        } else {
            // Set DO bit to 0
            // Uses AND NOT
            zField = zField & (~0x8000)
        }
        
        let ttl: UInt32 = (UInt32(extendedRcode) << 24) | (UInt32(version) << 16) | UInt32(zField)
        
        data.append(contentsOf: withUnsafeBytes(of: ttl.bigEndian) { Data($0) })
        var rdata: Data = Data()
        
        for opt in options {
            data.append(contentsOf: withUnsafeBytes(of: opt.code.rawValue.bigEndian) { Data($0) })
            var optionData = try opt.toData()
            rdata.append(contentsOf: withUnsafeBytes(of: optionData.count.bigEndian) { Data($0) })
            rdata.append(optionData)
        }
        
        let rdlength: UInt16 = UInt16(rdata.count).bigEndian
        data.append(contentsOf: withUnsafeBytes(of: rdlength) { Data($0) })
        data.append(rdata)
        
        return data
    }
    
    var description: String {
        var description = "EXT_RCODE=\(extendedRcode), VERSION=\(version), DO=\(doBit), OPTIONS:\n"
        for opt in options {
            description += "\(opt.description)\n"
            /*
            description += "\n\(opt.code.description): "
             
            for value in opt.values {
                description += "\(value.key)=\(value.value), "
            }*/
        }
        return description
    }
    
    public static func ==(lhs: EDNSMessage, rhs: EDNSMessage) -> Bool {
        return lhs.extendedRcode == rhs.extendedRcode && lhs.version == rhs.version && lhs.zField == rhs.zField && lhs.doBit == rhs.doBit && lhs.options == rhs.options
    }
}

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

/// The EDNS Options Codes
/// [Defined by iana](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
public enum EDNSOptionCode: UInt16, Sendable {
    case reserved = 0
    case LLQ = 1
    case updateLease = 2
    case NSID = 3
    case DAU = 5
    case DHU = 6
    case N3U = 7
    case ClientSubnet = 8
    case EDNSExpire = 9
    case COOKIE = 10
    case KeepAlive = 11
    case Padding = 12
    // https://www.rfc-editor.org/rfc/rfc8914.html
    case ExtendedDNSError = 15
    case unknown
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let type = try container.decode(UInt16.self)
        
        self.init(rawValue: type)!
    }
    
    /// A short user-friendly string that describes the EDNS Option Code
    public var description: String {
        switch self {
        case .reserved: return "RESERVED"
        case .LLQ: return "LLQ"
        case .updateLease: <#code#>
        case .NSID: return "NSID"
        case .DAU: return "DAU"
        case .DHU: return "DHU"
        case .N3U: return "N3U"
        case .ClientSubnet: return "Client Subnet"
        case .EDNSExpire: <#code#>
        case .COOKIE: return "Cookie"
        case .KeepAlive: return "KeepAlive"
        case .Padding: return "Padding"
        case .ExtendedDNSError: return "Extended DNS Error"
        case .unknown: return "Unkown: '\(self.rawValue)'"
        }
    }
    
    public static func == (lhs: EDNSOptionCode, rhs: EDNSOptionCode) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}


/// The extended DNS Extended DNS Codes  as defined by [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
public enum EDNSExtendedError: UInt16, Decodable, Equatable, Sendable, LosslessStringConvertible {
    case otherError = 0
    case unsupportedDNSKEYAlgorithm = 1
    case unsupportedDSDigestType = 2
    case staleAnswer = 3
    case forgedAnswer = 4
    case DNSSECIndeterminate = 5
    case DNSSECBogus = 6
    case signatureExpired = 7
    case signatureNotYetValid = 8
    case DNSKEYMissing = 9
    case RRSIGMissing = 10
    case noZoneKeyBit = 11
    case NSECMissing = 12
    case cachedError = 13
    case notReady = 14
    case blocked = 15
    case censored = 16
    case filtered = 17
    case prohibited = 18
    case staleNXDomainAnswer = 19
    case notAuthoritative = 20
    case notSupported = 21
    case noReachableAuthority = 22
    case networkError = 23
    case invalidData = 24
    case signatureExpiredBeforeValid = 25
    case tooEarly = 26
    case unsupportedNSEC3IterationsValue = 27
    case unableToConformToPolicy = 28
    case synthesized = 29
    case invalidQueryType = 30
    case unknown
    
    public init?(_ description: String) {
        switch description {
        case "Other Error":
            self = .otherError
        case "Unsupported DNSKEY Algorithm":
            self = .unsupportedDNSKEYAlgorithm
        case "Unsupported DS Digest Type" :
            self = .unsupportedDSDigestType
        case "Stale Answer":
            self = .staleAnswer
        case "Forged Answer":
            self = .forgedAnswer
        case "DNSSEC Indeterminate":
            self = .DNSSECIndeterminate
        case "DNSSEC Bogus":
            self = .DNSSECBogus
        case "Signature Expired":
            self = .signatureExpired
        case "Signature Not Yet Valid":
            self = .signatureNotYetValid
        case "DNSKEY Missing":
            self = .DNSKEYMissing
        case "RRSIGs Missing":
            self = .RRSIGMissing
        case "No Zone Key Bit Set":
            self = .noZoneKeyBit
        case "NSEC Missing":
            self = .NSECMissing
        case "Cached Error":
            self = .cachedError
        case "Not Ready":
            self = .notReady
        case "Blocked":
            self = .blocked
        case "Censored":
            self = .censored
        case "Filtered":
            self = .filtered
        case "Prohibited":
            self = .prohibited
        case "Stale NXDomain Answer":
            self = .staleNXDomainAnswer
        case "Not Authoritative":
            self = .notAuthoritative
        case "Not Supported":
            self = .notSupported
        case "No Reachable Authority":
            self = .noReachableAuthority
        case "Network Error":
            self = .networkError
        case "Invalid Data":
            self = .invalidData
        case "Signature Expired before Valid":
            self = .signatureExpiredBeforeValid
        case "Too Early":
            self = .tooEarly
        case "Unsupported NSEC3 Iterations Value":
            self = .unsupportedNSEC3IterationsValue
        case "Unable to conform to policy":
            self = .unableToConformToPolicy
        case "Synthesized":
            self = .synthesized
        case "Invalid Query Type":
            self = .invalidQueryType
        default:
            do {
                let pattern = "'(\\d+)'"
                let regex = try NSRegularExpression(pattern: pattern, options: [])
                if let result = regex.firstMatch(in: description, options: [], range: NSRange(description.startIndex..., in: description)) {
                    if let range = Range(result.range(at: 1), in: description) {
                        guard let value = UInt16(description[range]) else {
                            return nil
                        }
                        self.init(rawValue: value)
                    }
                }
            } catch {
                return nil
            }
        }
    }
    
    /// A short string that represents the RCode
    public var displayName: String {
        switch self {
        case .otherError:
            return "NoError"
        case .unsupportedDNSKEYAlgorithm:
            return "NoError"
        case .unsupportedDSDigestType:
            return "NoError"
        case .staleAnswer:
            return "NoError"
        case .forgedAnswer:
            return "NoError"
        case .DNSSECIndeterminate:
            return "NoError"
        case .DNSSECBogus:
            return "NoError"
        case .signatureExpired:
            return "NoError"
        case .signatureNotYetValid:
            return "NoError"
        case .DNSKEYMissing:
            return "NoError"
        case .RRSIGMissing:
            return "NoError"
        case .noZoneKeyBit:
            return "NoError"
        case .NSECMissing:
            return "NoError"
        case .cachedError:
            return "NoError"
        case .notReady:
            return "NoError"
        case .blocked:
            return "NoError"
        case .censored:
            return "NoError"
        case .filtered:
            return "NoError"
        case .prohibited:
            return "NoError"
        case .staleNXDomainAnswer:
            return "NoError"
        case .notAuthoritative:
            return "NoError"
        case .notSupported:
            return "NoError"
        case .noReachableAuthority:
            return "NoError"
        case .networkError:
            return "NoError"
        case .invalidData:
            return "NoError"
        case .signatureExpiredBeforeValid:
            return "NoError"
        case .tooEarly:
            return "tooEarly"
        case .unsupportedNSEC3IterationsValue:
            return "NoError"
        case .unableToConformToPolicy:
            return "NoError"
        case .synthesized:
            return "NoError"
        case .invalidQueryType:
            return "NoError"
        case .unknown:
            return "Unkown '\(rawValue)'"
        }
    }
    
    /// A short user-friendly string that describes the RCode
    public var description: String {
        switch self {
        case .otherError:
            return "Other Error"
        case .unsupportedDNSKEYAlgorithm:
            return "Unsupported DNSKEY Algorithm"
        case .unsupportedDSDigestType:
            return "Unsupported DS Digest Type"
        case .staleAnswer:
            return "Stale Answer"
        case .forgedAnswer:
            return "Forged Answer"
        case .DNSSECIndeterminate:
            return "DNSSEC Indeterminate"
        case .DNSSECBogus:
            return "DNSSEC Bogus"
        case .signatureExpired:
            return "Signature Expired"
        case .signatureNotYetValid:
            return "Signature Not Yet Valid"
        case .DNSKEYMissing:
            return "DNSKEY Missing"
        case .RRSIGMissing:
            return "RRSIGs Missing"
        case .noZoneKeyBit:
            return "No Zone Key Bit Set"
        case .NSECMissing:
            return "NSEC Missing"
        case .cachedError:
            return "Cached Error"
        case .notReady:
            return "Not Ready"
        case .blocked:
            return "Blocked"
        case .censored:
            return "Censored"
        case .filtered:
            return "Filtered"
        case .prohibited:
            return "Prohibited"
        case .staleNXDomainAnswer:
            return "Stale NXDomain Answer"
        case .notAuthoritative:
            return "Not Authoritative"
        case .notSupported:
            return "Not Supported"
        case .noReachableAuthority:
            return "No Reachable Authority"
        case .networkError:
            return "Network Error"
        case .invalidData:
            return "Invalid Data"
        case .signatureExpiredBeforeValid:
            return "Signature Expired before Valid"
        case .tooEarly:
            return "Too Early"
        case .unsupportedNSEC3IterationsValue:
            return "Unsupported NSEC3 Iterations Value"
        case .unableToConformToPolicy:
            return "Unable to conform to policy"
        case .synthesized:
            return "Synthesized"
        case .invalidQueryType:
            return "Invalid Query Type"
        case .unknown:
            return "unknown. Value: '\(rawValue)'"
        }
    }
    
    public static func ==(lhs: EDNSExtendedError, rhs: EDNSExtendedError) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }
}
