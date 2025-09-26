//
//  QueryResult.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

/// A DNS response
public struct QueryResult: Sendable {
    /// The DNS response headers
    public var header: DNSHeader
    
    /// The questions sent
    public var Question: [QuestionSection]
    /// The answers returned
    public var Answer: [ResourceRecord]
    /// The authority records returned
    public var Authority: [ResourceRecord]
    /// The additional records returned
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
