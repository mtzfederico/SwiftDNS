//
//  DNSMessage.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// A DNS response
public struct DNSMessage: Sendable {
    /// The DNS response headers
    public var header: DNSHeader
    
    /// The questions section
    ///
    /// This should always contain only one question in normal operations.
    /// Read [RFC9619](https://datatracker.ietf.org/doc/rfc9619/) for more details
    public var Question: [QuestionSection] = []
    /// The answers section
    public var Answer: [ResourceRecord] = []
    /// The authority records section
    public var Authority: [ResourceRecord] = []
    /// The additional records section
    public var Additional: [ResourceRecord] = []
    
    public var EDNSData: EDNSMessage?
    
    public init(header: DNSHeader, Question: [QuestionSection], Answer: [ResourceRecord], Authority: [ResourceRecord], Additional: [ResourceRecord], EDNSData: EDNSMessage? = nil) {
        self.header = header
        self.Question = Question
        self.Answer = Answer
        self.Authority = Authority
        self.Additional = Additional
        self.EDNSData = EDNSData
    }
    
    /// Parses a DNS response
    /// - Parameter data: The data representing the DNS response
    /// - Returns: The parsed DNS response
    public init(data: Data) throws {
        // Make sure that there is enough data for the header.
        // 6 sections of 2 bytes (16 bits) = 6 * 2 = 12
        guard data.count > 12 else {
            throw DNSError.invalidData("DNS data too small. Cannot parse header.")
        }
        
        var offset = 0
        
        self.header = try DNSHeader(data: data, offset: &offset)
        
        // The questions only have QNAME, QTYPE, and QCLASS
        
        for _ in 0..<header.QDCOUNT {
            let rr = try QuestionSection(data: data, offset: &offset)
            self.Question.append(rr)
        }
        
        for _ in 0..<header.ANCOUNT {
            let rr = try ResourceRecord(data: data, offset: &offset)
            self.Answer.append(rr)
        }
        
        for _ in 0..<header.NSCOUNT {
            let rr = try ResourceRecord(data: data, offset: &offset)
            self.Authority.append(rr)
        }
        
        for _ in 0..<header.ARCOUNT {
            do {
                let rr = try ResourceRecord(data: data, offset: &offset)
                self.Additional.append(rr)
            } catch DNSError.invalidData("OPT_RECORD") {
                self.EDNSData = try EDNSMessage(data: data, offset: &offset)
            } catch(let error) {
                throw error
            }
        }
    }
    
    /// Encodes the DNSMessage into Data
    /// - Returns: The DNSMessage as Data
    public func toData() throws -> Data {
        var data: Data = header.toData()
        
        if header.QDCOUNT == 1 && header.ANCOUNT == 0 && header.NSCOUNT == 0 && header.ARCOUNT == 0 {
            guard let question = Question.first else {
                throw DNSError.invalidData("No question in message")
            }
            data.append(try question.toData(includeName: true))
            
            if let ednsData = EDNSData {
                data.append(try ednsData.toData())
            }
            return data
        }
        
        var nameOffsets: [String: Int] = [:]
        
        for question in Question {
            let encodedDomain = try DNSMessage.encodeDomainName(name: question.QNAME, messageLength: data.count, nameOffsets: &nameOffsets)
            data.append(encodedDomain)
            data.append(try question.toData(includeName: false))
        }
        
        for rr in Answer {
            // data.append(try DNSClient.encodeDomainName(name: rr.name, messageLength: data.count, nameOffsets: &nameOffsets))
            data.append(try rr.toData(messageLength: data.count, nameOffsets: &nameOffsets))
        }
        
        for rr in Authority {
            data.append(try rr.toData(messageLength: data.count, nameOffsets: &nameOffsets))
        }
        
        for rr in Additional {
            data.append(try rr.toData(messageLength: data.count, nameOffsets: &nameOffsets))
        }
        
        if let ednsData = EDNSData {
            data.append(try ednsData.toData())
        }
        
        return data
    }
    
    /// Returns a multiline description of the DNS Message.
    public var description: String {
        var desc = ";; header: \(header.description())\n;; Questions:\n"
        
        for q in Question {
            desc.append("\(q.description)\n")
        }
        
        desc.append(";; Answer:\n")
        for rr in Answer {
            desc.append("\(rr.description)\n")
        }
        
        desc.append(";; Authority:\n")
        for rr in Authority {
            desc.append("\(rr.description)\n")
        }
        
        desc.append(";; Additional:\n")
        for rr in Additional {
            desc.append("\(rr.description)\n")
        }
        
        if let edns = self.EDNSData {
            desc.append(";; EDNS:\n")
            desc.append("\(edns.description)\n")
        }
        
        return desc
    }
    
    /// Encodes a domain name with compression support
    /// - Parameters:
    ///   - name: The domain name to encode
    ///   - messageLength: The length of the message  so far (for computing pointer offsets).
    ///   - nameOffsets: A map of previously seen suffixes to their offset
    /// - Returns: The encoded domain name
    public static func encodeDomainName(name: String, messageLength: Int, nameOffsets: inout [String: Int]) throws -> Data {
        // Each label is represented by the number of characters (8 bits) followed by the chracters themselves (each one is 8 bits).
        // When using compression, the whole thing is 16 bits. the left-most 2 bits are 1 and the following 14 bits are the position to go to.
        // https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
        //
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 1  1|                OFFSET                   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        
        var data = Data()
        var currentOffset = messageLength

        let labels = name.split(separator: ".")
        var i = 0

        // Look for labels already found in order from most to least. Once it is found it exits the loop.
        // For www.example.com, the irst run will use 'www.example.com'. The second 'example.com', and the third 'com'.
        
        while i < labels.count {
            if labels[i].count > 63 {
                throw DNSError.invalidData("DNS label cannot have more than 63 characters. Label has \(labels[i].count) characters")
            }
            
            let suffix = labels[i...].joined(separator: ".")
            
            if let pointerOffset = nameOffsets[suffix] {
                // Use compression pointer. 0xC000 is the two left-most bits set to 1
                let pointer = UInt16(pointerOffset) | 0xC000
                data.append(contentsOf: withUnsafeBytes(of: pointer.bigEndian) { Data($0) })
                // print("Using pointer (\(String(format: "%02hhx", pointer)) \(String(format: "%02hhx", pointer+1))) to suffix \(suffix) at currentOffset \(currentOffset).")
                return data
            }

            // print("Saving pointer for suffix \(suffix) at currentOffset \(currentOffset).")
            
            // Record this suffix's offset if not already recorded
            nameOffsets[suffix] = currentOffset

            let label = labels[i]
            data.append(UInt8(label.count))
            data.append(contentsOf: label.utf8)

            currentOffset += 1 + label.count
            i += 1
        }

        data.append(0) // End of name
        return data
    }
    
    public static func ==(lhs: DNSMessage, rhs: DNSMessage) -> Bool {
        let edns: Bool = {
            if lhs.EDNSData == nil && rhs.EDNSData == nil {
                return true
            }
            
            return lhs.EDNSData! == rhs.EDNSData!
        }()
        
        return lhs.header == rhs.header && lhs.Question == rhs.Question && lhs.Answer == rhs.Answer && lhs.Authority == rhs.Authority && lhs.Additional == rhs.Additional && edns
    }
}
