//
//  DNSCoder.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation

final public class DNSCoder: Sendable {
    /// Retuns the data for the query and the ID
    public func encodeQuery(question: QuestionSection) -> (Data, UInt16) {
        let id = UInt16.random(in: 0...UInt16.max)
        let flags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        // print((String(format:"%02x", flags.toRaw())))
        
        let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0).toData()
        // let question = QuestionSection(host: host, type: type, CLASS: .internet).toData()
        
        let data: Data = header + question.toData()
        return (data, id)
    }
    
    public func parseDNSResponse(_ data: Data) throws -> QueryResult {
        guard data.count > 12 else {
            // print("[parseDNSResponse] Invalid DNS response. Count over 12")
            throw DNSError.invalidData
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
        
        /*
        if answers.count != header.ANCOUNT {
            print("answers.count != answerCount")
        }
        
        if authority.count != header.NSCOUNT {
            print("authority.count != nscount")
        }
        
        if additional.count != header.ARCOUNT {
            print("additional.count != arcount")
        }*/
        
        return QueryResult(header: header, Question: questions, Answer: answers, Authority: authority, Additional: additional)
    }
    
    public static func parseDomainName(data: Data, offset: Int) -> (String, Int) {
        var labels: [String] = []
        var currentOffset = offset
        var consumed = 0

        while currentOffset < data.count {
            let length = Int(data[currentOffset])

            // Null label
            if length == 0 {
                consumed = currentOffset - offset + 1
                break
            }

            // Compressed label (pointer: 11xx xxxx)
            if length & 0xC0 == 0xC0 {
                if currentOffset + 1 >= data.count { break }
                let byte2 = Int(data[currentOffset + 1])
                let pointer = ((length & 0x3F) << 8) | byte2
                let (jumpedName, _) = parseDomainName(data: data, offset: pointer)
                labels.append(jumpedName)
                consumed = currentOffset - offset + 2
                break
            } else {
                let labelStart = currentOffset + 1
                let labelEnd = labelStart + length
                guard labelEnd <= data.count else { break }
                let labelData = data[labelStart..<labelEnd]
                if let label = String(data: labelData, encoding: .utf8) {
                    labels.append(label)
                }
                currentOffset = labelEnd
                consumed = currentOffset - offset
            }
        }

        return (labels.joined(separator: "."), consumed)
    }
}

/// A DNS response
public struct QueryResult {
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
