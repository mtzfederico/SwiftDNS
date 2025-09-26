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
