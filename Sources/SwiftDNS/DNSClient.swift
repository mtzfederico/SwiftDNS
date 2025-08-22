//
//  DNSClient.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation
import Network
import Logging

public enum DNSConnectionType: Sendable {
    case dnsOverTLS
    case dnsOverHTTPS
    case dnsOverUDP
    case dnsOverTCP
}

final public class DNSClient: Sendable {
    let logger: Logger
    private let dnsCoder = DNSCoder()
    private let connection: NWConnection?
    private let connectionType: DNSConnectionType
    private let server: String
    
    public init(server: String, connectionType: DNSConnectionType, logger: Logger = Logger(label: "com.mtzfederico.SwiftDNS")) {
        self.logger = logger
        self.server = server
        self.connectionType = connectionType
        
        switch connectionType {
        case .dnsOverTLS:
            self.connection = NWConnection(host: .name(server, nil), port: 853, using: .tls)
        case .dnsOverUDP:
            self.connection = NWConnection(host: .name(server, nil), port: 53, using: .udp)
        case .dnsOverTCP:
            self.connection = NWConnection(host: .name(server, nil), port: 53, using: .tcp)
        case .dnsOverHTTPS:
            self.connection = nil
        }
    }
    
    @available(macOS 10.15, iOS 13.0, *)
    public func query(host: String, type: DNSRecordType, Class: DNSClass) async throws -> QueryResult {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(host: host, type: type, Class: Class, completion: { result in
                continuation.resume(with: result)
            })
        }
    }
    
    public func query(host: String, type: DNSRecordType, Class: DNSClass, completion: @escaping @Sendable (sending Result<QueryResult, Error>) -> ()) {
        switch connectionType {
        case .dnsOverTLS, .dnsOverTCP:
            return sendTCP(host: host, type: type, Class: Class, completion: completion)
        case .dnsOverUDP:
            return sendUDP(host: host, type: type, Class: Class, completion: completion)
        case .dnsOverHTTPS:
            return sendHTTPS(host: host, type: type, Class: Class, completion: completion)
        }
    }
    
    private func sendTCP(host: String, type: DNSRecordType, Class: DNSClass, completion: @escaping @Sendable (sending Result<QueryResult, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        let (query, id) = dnsCoder.encodeQuery(question: QuestionSection(host: host, type: type, CLASS: Class))
        
        // TCP has a 2-byte prefix with the length because it is a stram of data and it needs to know how long all of it is
        // In UDP, the whole packet is a single request. In TCP (and TLS) the data can go over multiple packets/frames
        let lengthPrefix = UInt16(query.count)
        
        let data: Data = Data(withUnsafeBytes(of: lengthPrefix.bigEndian, Array.init)) + query
        
        logger.trace("[sendTCP] Sending query", metadata: ["host": "\(host)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
        
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.logger.debug("[sendTCP] Connection ready, sending data...")
                // Send DNS query
                connection.send(content: data, completion: .contentProcessed { sendError in
                    if let error = sendError {
                        completion(.failure(DNSError.connectionFailed(error)))
                        return
                    }
                    
                    connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { lengthData, _, _, error in
                        if let error = error {
                            completion(.failure(DNSError.connectionFailed(error)))
                            return
                        }
                        
                        guard let lengthData = lengthData else {
                            completion(.failure(DNSError.noDataReceived))
                            return
                        }
                        
                        if lengthData.count != 2 {
                            self.logger.trace("[sendTCP] Received invalid lengthData", metadata: ["response": "\(lengthData.hexEncodedString())"])
                            completion(.failure(DNSError.invalidData))
                            return
                        }
                        
                        let length = Int(lengthData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                        
                        // Get the actual data
                        connection.receive(minimumIncompleteLength: length, maximumLength: length) { data, _, _, error in
                            if let error = error {
                                completion(.failure(DNSError.connectionFailed(error)))
                                return
                            }
                            
                            guard let data = data else {
                                completion(.failure(DNSError.invalidData))
                                return
                            }
                            
                            self.logger.trace("[sendTCP] Received DNS response", metadata: ["data": "\(data.hexEncodedString())"])
                            
                            do {
                                let result = try self.dnsCoder.parseDNSResponse(data)
                                completion(.success(result))
                            } catch {
                                completion(.failure(error))
                            }
                        }
                    }
                })
            case .failed(let error):
                completion(.failure(DNSError.connectionFailed(error)))
                return
            case .waiting(let error):
                self.logger.info("[sendTCP] Connection waiting", metadata: ["error": "\(error.localizedDescription)"])
            case .preparing:
                self.logger.debug("[sendTCP] Connection preparing...")
            default:
                completion(.failure(DNSError.unknownState(state)))
                break
            }
        }
        
        logger.debug("[sendTCP] Starting connection...")
        connection.start(queue: .global())
    }
    
    private func sendUDP(host: String, type: DNSRecordType, Class: DNSClass, completion: @escaping @Sendable (sending Result<QueryResult, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        let id = UInt16.random(in: 0...UInt16.max)
        let flags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        // print((String(format:"%02x", flags.toRaw())))
        
        let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0).toData()
        let question = QuestionSection(host: host, type: type, CLASS: Class).toData()
        
        let data: Data = header + question
        
        logger.trace("[sendUDP] Sending query", metadata: ["host": "\(host)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
        
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.logger.debug("[sendUDP] Connection ready, sending data...")
                
                // Send DNS query
                connection.send(content: data, completion: .contentProcessed { sendError in
                    if let error = sendError {
                        completion(.failure(DNSError.connectionFailed(error)))
                        return
                    }
                })
            case .failed(let error):
                completion(.failure(DNSError.connectionFailed(error)))
                return
            case .waiting(let error):
                self.logger.info("[sendUDP] Connection waiting", metadata: ["error": "\(error.localizedDescription)"])
            case .preparing:
                self.logger.debug("[sendUDP] Connection preparing...")
            default:
                completion(.failure(DNSError.unknownState(state)))
                break
            }
        }
        
        // Wait for response (asynchronously)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, context, isComplete, error in
            do {
                if let error = error {
                    completion(.failure(DNSError.connectionFailed(error)))
                    return
                }
                if let data = data {
                    self.logger.trace("[sendUDP] Received DNS response", metadata: ["data": "\(data.hexEncodedString())"])
                    
                    let result = try self.dnsCoder.parseDNSResponse(data)
                    completion(.success(result))
                }
            } catch {
                completion(.failure(DNSError.parsingError(error)))
            }
        }
        
        logger.debug("[sendUDP] Starting connection...")
        connection.start(queue: .global())
    }
    
    // @available(iOS 15.0, *)
    private func sendHTTPS(host: String, type: DNSRecordType, Class: DNSClass, completion: @escaping @Sendable (sending Result<QueryResult, Error>) -> ()) {
        guard let url = URL(string: server) else {
            completion(.failure(DNSError.invalidServerAddress))
            // throw DNSError.invalidServerAddress
            return
        }
        
        let (data, id) = dnsCoder.encodeQuery(question: QuestionSection(host: host, type: type, CLASS: .internet))
        
        logger.trace("[sendHTTPS] Sending query", metadata: ["host": "\(host)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.httpBody = data
        
        let task = URLSession.shared.dataTask(with: request, completionHandler: { responseData, response, error in
            guard error == nil, let responseData = responseData else {
                completion(.failure(DNSError.parsingError(error)))
                return
            }
            
            do {
                let status = (response as! HTTPURLResponse).statusCode
                self.logger.debug("[sendHTTPS] HTTP Response", metadata: ["status": "\(status)", "mime": "\(response?.mimeType ?? "<nil>")"])
                self.logger.trace("[sendHTTPS] Received DNS response", metadata: ["data": "\(data.hexEncodedString())"])
                
                let result = try self.dnsCoder.parseDNSResponse(responseData)
                completion(.success(result))
            } catch(let error) {
                completion(.failure(error))
            }
        })
        task.resume()
        
        /*
        let (responseData, response) = try await URLSession.shared.data(for: request)
        let status = (response as! HTTPURLResponse).statusCode
        self.logger.debug("[sendHTTPS] Status: \(status), mime: \(response.mimeType ?? "<nil>")")
        self.logger.trace("[sendHTTPS] Received DNS response: \(responseData.hexEncodedString())")
        // print("[sendHTTPS] response header: \(responseHeader.description())")
        
        return try self.dnsCoder.parseDNSResponse(responseData)
         */
    }
}
