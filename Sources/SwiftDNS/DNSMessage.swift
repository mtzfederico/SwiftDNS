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
    
    public init(header: DNSHeader, Question: [QuestionSection], Answer: [ResourceRecord], Authority: [ResourceRecord], Additional: [ResourceRecord]) {
        self.header = header
        self.Question = Question
        self.Answer = Answer
        self.Authority = Authority
        self.Additional = Additional
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
            let rr = try ResourceRecord(data: data, offset: &offset)
            self.Additional.append(rr)
        }
    }
    
    /// Encodes the DNSMessage into Data
    /// - Returns: The DNSMessage as Data
    public func toData() throws -> Data {
        #warning("it can only encode the header and the question")
        guard let question = Question.first else {
            throw DNSError.invalidData("No question in message")
        }
        
        let data: Data = header.toData() + question.toData()
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
        
        return desc
    }
}
