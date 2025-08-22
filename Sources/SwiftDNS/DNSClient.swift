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
        
        logger.trace("[sendTCP] Sending query for \(host) with id: 0x\(String(format:"%02x", id))")
        
        // TCP has a 2-byte prefix with the length because it is a stram of data and it needs to know how long all of it is
        // In UDP, the whole packet is a single request. In TCP (and TLS) the data can go over multiple packets/frames
        let lengthPrefix = UInt16(query.count)
        
        let data: Data = Data(withUnsafeBytes(of: lengthPrefix.bigEndian, Array.init)) + query
        
        logger.trace("[sendTCP] Data being sent: \(data.hexEncodedString())")
        
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.logger.trace("[sendTCP] Connection ready, sending data...")
                // Send DNS query
                connection.send(content: data, completion: .contentProcessed { sendError in
                    if let error = sendError {
                        // print("sendTCP] Error sending data: \(error.localizedDescription)")
                        completion(.failure(DNSError.connectionFailed(error)))
                        return
                    }
                    
                    connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { lengthData, _, _, error in
                        if let error = error {
                            self.logger.error("[sendTCP] Error receiving lengthData: \(error.localizedDescription)")
                            completion(.failure(DNSError.connectionFailed(error)))
                            return
                        }
                        
                        guard let lengthData = lengthData else {
                            self.logger.error("[sendTCP] Received nil lengthData response")
                            completion(.failure(DNSError.noDataReceived))
                            return
                        }
                        
                        if lengthData.count != 2 {
                            self.logger.error("[sendTCP] Received invalid lengthData response: \(lengthData.hexEncodedString())")
                            completion(.failure(DNSError.invalidData))
                            return
                        }
                        
                        let length = Int(lengthData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                        self.logger.trace("[sendTCP] Received length: \(length)")
                        
                        // Get the actual data
                        connection.receive(minimumIncompleteLength: length, maximumLength: length) { data, _, _, error in
                            if let error = error {
                                self.logger.error("[sendTLS] Error receiving data: \(error.localizedDescription)")
                                completion(.failure(DNSError.connectionFailed(error)))
                                return
                            }
                            
                            guard let data = data else {
                                completion(.failure(DNSError.invalidData))
                                return
                            }
                            
                            self.logger.trace("[sendTCP] Received DNS response: \(data.hexEncodedString())")
                            
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
                self.logger.error("[sendTCP] Connection failed: \(error.localizedDescription)")
                completion(.failure(DNSError.connectionFailed(error)))
                return
            case .waiting(let error):
                self.logger.debug("[sendTCP] Connection waiting: \(error.localizedDescription)")
            case .preparing:
                self.logger.debug("[sendTCP] Connection preparing...")
            default:
                self.logger.error("[sendTCP] Unknown connection state")
                completion(.failure(DNSError.unknownState))
                break
            }
        }
        
        logger.trace("[sendTCP] Starting connection...")
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
        
        logger.trace("[sendUDP] Sending query for \(host) with id: 0x\(String(format:"%02x", id))")
        
        let data: Data = header + question
        
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                self.logger.trace("[sendUDP] Connection ready, sending data...")
                
                // Send DNS query
                connection.send(content: data, completion: .contentProcessed { sendError in
                    if let error = sendError {
                        print("[sendUDP] Error sending data: \(error.localizedDescription)")
                        return
                    }
                })
            case .failed(let error):
                self.logger.error("[sendUDP] Connection failed: \(error.localizedDescription)")
                completion(.failure(DNSError.connectionFailed(error)))
                return
            case .waiting(let error):
                self.logger.debug("[sendUDP] Connection waiting: \(error.localizedDescription)")
            case .preparing:
                self.logger.debug("[sendUDP] Connection preparing...")
            default:
                self.logger.error("[sendUDP] Unknown connection state")
                completion(.failure(DNSError.unknownState))
                break
            }
        }
        
        // Wait for response (asynchronously)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, context, isComplete, error in
            do {
                if let error = error {
                    self.logger.error("[sendUDP] Error receiving data: \(error.localizedDescription)")
                    completion(.failure(DNSError.connectionFailed(error)))
                    return
                }
                if let data = data {
                    self.logger.trace("[sendUDP] Received DNS response: \(data.hexEncodedString())")
                    
                    let result = try self.dnsCoder.parseDNSResponse(data)
                    completion(.success(result))
                }
            } catch {
                print("[sendUDP] Error parsing DNS response: \(error.localizedDescription)")
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
        
        logger.trace("[sendHTTPS] Sending query for \(host) with id: 0x\(String(format:"%02x", id))")
        // print("[sendHTTPS] Sending: \(data.hexEncodedString())")
        
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
                self.logger.debug("[sendHTTPS] Status: \(status), mime: \(response?.mimeType ?? "<nil>")")
                
                // print("[sendHTTPS] Received DNS response: \(responseData.hexEncodedString())")
                // print("[sendHTTPS] response header: \(responseHeader.description())")
                
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
        
        // print("[sendHTTPS] Received DNS response: \(responseData.hexEncodedString())")
        // print("[sendHTTPS] response header: \(responseHeader.description())")
        
        return try self.dnsCoder.parseDNSResponse(responseData)
         */
    }
}
