//
//  DNSMessage.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// A DNS response
public struct DNSMessage: Sendable {
    // TODO: make it reusable for sending and receiving.
    // add a function to encode
    
    /// The DNS response headers
    public var header: DNSHeader
    
    /// The questions section
    public var Question: [QuestionSection]
    /// The answers section
    public var Answer: [ResourceRecord]
    /// The authority records section
    public var Authority: [ResourceRecord]
    /// The additional records section
    public var Additional: [ResourceRecord]
    
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
        // Make sure that there is enough data for the header
        guard data.count > 12 else {
            throw DNSError.invalidData("DNS data too small. Cannot parse header.")
        }
        
        var offset = 0
        
        let header: DNSHeader = try DNSHeader(data: data, offset: &offset)
        
        // The questions only have QNAME, QTYPE, and QCLASS
        var questions: [QuestionSection] = []
        
        var answers: [ResourceRecord] = []
        var authority: [ResourceRecord] = []
        var additional: [ResourceRecord] = []
        
        
        for _ in 0..<header.QDCOUNT {
            let rr = try QuestionSection(data: data, offset: &offset)
            questions.append(rr)
        }
        
        for _ in 0..<header.ANCOUNT {
            let rr = try ResourceRecord(data: data, offset: &offset)
            answers.append(rr)
        }
        
        for _ in 0..<header.NSCOUNT {
            let rr = try ResourceRecord(data: data, offset: &offset)
            authority.append(rr)
        }
        
        for _ in 0..<header.ARCOUNT {
            let rr = try ResourceRecord(data: data, offset: &offset)
            additional.append(rr)
        }
        
        self = DNSMessage(header: header, Question: questions, Answer: answers, Authority: authority, Additional: additional)
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
