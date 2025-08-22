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
}
