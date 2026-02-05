//
//  DNSClient.swift
//  SwiftDNS
//
//  Created by mtzfederico on 2025-08-18
// 

import Foundation
import Network
import Logging

/// The connection type used to send DNS requests
public enum DNSConnectionType: Sendable, CustomStringConvertible, CaseIterable {
    case dnsOverTLS
    case dnsOverHTTPS
    case dnsOverUDP
    case dnsOverTCP
    
    /// Describes the connection type in a short string with no spaces
    public var description: String {
        switch self {
        case .dnsOverTLS:
            return "DoT"
        case .dnsOverHTTPS:
            return "DoH"
        case .dnsOverUDP:
            return "DoUDP"
        case .dnsOverTCP:
            return "DoTCP"
        }
    }
}

/// The DNS Cient used to send DNS queries
///
/// Initialize it with the server's IP or hostname and the connection type and use the Query method to send DNS queries
final public actor DNSClient: Sendable {
    private let dnsQueue: DispatchQueue
    /// The logger used
    private let logger: Logger
    /// The NWConnection used to send UDP, TCP, and TLS queries. HTTP queries use URLSession.shared
    private let connection: NWConnection?
    /// The connection type used to send the request
    private let connectionType: DNSConnectionType
    /// The server used to send the query to
    private let server: String
    /// The URL Session used when sending queries over HTTPS
    private var urlSession: URLSession?
    
    private var isConnected: Bool = false
    
    /// DNSClass Initialiser
    /// - Parameters:
    ///   - server: The server to send the query to. For UDP and TCP, it can be an IP or a domain. For TLS it should be a domain name (Ex: "dns.quad9.net" or "one.one.one.one"), and for HTTPS it sould be a URL (Ex: "https://cloudflare-dns.com/dns-query" or "https://dns.quad9.net/dns-query")
    ///   - connectionType: The DNS conecction type to use. UDP, TCP, TLS, or HTTPS
    ///   - urlSession: An optional instance of URLSession to use for DoH. If the connectionType is not dnsOverHTTPS, it is ignored.
    ///   - logger: The logger used
    public init(server: String, connectionType: DNSConnectionType, urlSession: URLSession? = nil,  logger: Logger = Logger(label: "com.mtzfederico.SwiftDNS")) {
        self.dnsQueue = DispatchQueue(label: "DNSClient-\(server.replacingOccurrences(of: " ", with: "_"))_\(connectionType.description)", attributes: .concurrent)
        self.logger = logger
        self.server = server
        self.connectionType = connectionType
        
        switch connectionType {
        case .dnsOverTLS:
            // self.connection = NWConnection(host: .name(server, nil), port: 853, using: .tls)
            let parameters = NWParameters.tls
            parameters.serviceClass = .responsiveData
            parameters.expiredDNSBehavior = .allow
            self.connection = NWConnection(to: .hostPort(host: .name(server, nil), port: 853), using: parameters)
        case .dnsOverUDP:
            self.connection = NWConnection(host: .name(server, nil), port: 53, using: .udp)
        case .dnsOverTCP:
            self.connection = NWConnection(host: .name(server, nil), port: 53, using: .tcp)
        case .dnsOverHTTPS:
            let config = URLSessionConfiguration.default
            config.httpAdditionalHeaders = ["User-Agent": "SwiftDNS/1.0 (+https://github.com/mtzfederico/SwiftDNS)"]
            self.urlSession = URLSession(configuration: config, delegate: nil, delegateQueue: nil)
            self.connection = nil
        }
    }
    
    private func setConnected(_ value: Bool) {
        self.isConnected = value
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    /// - Returns: The DNS response
    @available(macOS 10.15, iOS 13.0, *)
    public func query(host: String, type: DNSRecordType, Class: DNSClass = .internet, EDNS: EDNSMessage? = nil) async throws -> DNSMessage {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(host: host, type: type, Class: Class, EDNS: EDNS, completion: { result in
                continuation.resume(with: result)
            })
        }
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameter message: The DNS Message to send
    /// - Returns: The DNS response
    @available(macOS 10.15, iOS 13.0, *)
    public func query(message: DNSMessage) async throws -> DNSMessage {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(message: message, completion: { result in
                continuation.resume(with: result)
            })
        }
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    public func query(host: String, type: DNSRecordType, Class: DNSClass = .internet, EDNS: EDNSMessage? = nil, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        do {
            if host.isEmpty || !host.isDNSSafe {
                completion(.failure(DNSError.invalidDomainName))
                return
            }
            
            let id = UInt16.random(in: 0...UInt16.max)
            let flags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
            let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: EDNS != nil ? 1 : 0)
            
            let question = QuestionSection(host: host, type: type, CLASS: Class)
            let message = DNSMessage(header: header, Question: [question], Answer: [], Authority: [], Additional: [], EDNSData: EDNS)
            
            return query(message: message, completion: completion)
        } catch(let error) {
            completion(.failure(error))
        }
    }
    
    /// /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - message: The DNS Message to send
    ///   - completion: The DNS response or an Error
    public func query(message: DNSMessage, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        switch connectionType {
        case .dnsOverTLS, .dnsOverTCP:
            return sendTCP(message: message, completion: completion)
        case .dnsOverUDP:
            return sendUDP(message: message, completion: completion)
        case .dnsOverHTTPS:
            return sendHTTPS(message: message, completion: completion)
        }
    }
    
    private func startConnection() throws {
        // if isConnected { return }
        guard let connection else {
            throw DNSError.connectionIsNil
        }
        
        connection.start(queue: dnsQueue)
        setConnected(true)
        
        // #warning("Implement me")
        // use this to start the connection
        // keep isConnected state, call it when sending a request.
        // if not connected, connect. On connection failure restart the connection
    }
    
    /// Closes all connections  gracefully.
    public func closeConnections() {
        logger.trace("Closing Connection")
        self.connection?.cancel()
        setConnected(false)
    }
    
    /// Sends a DNS request to the server using TCP
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    private func sendTCP(message: DNSMessage, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        do {
            let id = message.header.id
            let query = try message.toData()
            
            // TCP has a 2-byte prefix with the length because it is a stram of data and it needs to know how long all of it is
            // In UDP, the whole packet is a single request. In TCP (and TLS) the data can go over multiple packets/frames
            let lengthPrefix = UInt16(query.count)
            
            let data: Data = Data(withUnsafeBytes(of: lengthPrefix.bigEndian, Array.init)) + query
            
            logger.trace("[sendTCP] Sending query", metadata: ["host": "\(message.Question[0].QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    Task {
                        await self.setConnected(true)
                    }
                    self.logger.debug("[sendTCP] Connection ready, sending data...")
                    // Send DNS query
                    connection.send(content: data, completion: .contentProcessed { sendError in
                        if let error = sendError {
                            #warning("if the connection fails, it should be restarted. Add some logic to only run this a few times")
                            Task {
                                await self.closeConnections()
                                self.logger.error("[sendTCP] Send failed. Restarting...",  metadata: ["error": "\(error.localizedDescription)"])
                                // restart the connection
                                await self.sendTCP(message: message, completion: completion)
                            }
                            
                            return
                            
                            // completion(.failure(DNSError.connectionFailed(error)))
                            // return
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
                                completion(.failure(DNSError.invalidData("Failed to parse length of data")))
                                return
                            }
                            
                            let length = Int(lengthData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                            
                            // Get the actual data
                            connection.receive(minimumIncompleteLength: length, maximumLength: length) { responseData, _, _, error in
                                if let error = error {
                                    completion(.failure(DNSError.connectionFailed(error)))
                                    return
                                }
                                
                                guard let responseData = responseData else {
                                    self.logger.trace("[sendTCP] Received data is nil")
                                    completion(.failure(DNSError.invalidData("Response is empty")))
                                    return
                                }
                                
                                self.logger.trace("[sendTCP] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                                
                                do {
                                    let result = try DNSMessage(data: responseData)
                                    // check that the id in the response is the same as the one sent in the query
                                    if result.header.id != id {
                                        self.logger.trace("[sendTCP] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                                        completion(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                                        return
                                    }
                                    completion(.success(result))
                                } catch {
                                    completion(.failure(error))
                                }
                            }
                        }
                    })
                case .failed(let error):
                    #warning("make sure this works")
                    // _Concurrency/CheckedContinuation.swift:196: Fatal error: SWIFT TASK CONTINUATION MISUSE: query(host:type:Class:) tried to resume its continuation more than once, throwing connectionFailed(POSIXErrorCode(rawValue: 54): Connection reset by peer)!
                    
                    // if error  == POSIXErrorCode(rawValue: 54) { }
                    Task {
                        await self.closeConnections()
                        self.logger.error("[sendTCP] Connection failed. Restarting...",  metadata: ["error": "\(error.localizedDescription)"])
                        // restart the connection
                        await self.sendTCP(message: message, completion: completion)
                    }
                    
                    // completion(.failure(DNSError.connectionFailed(error)))
                    return
                case .cancelled:
                    Task {
                        await self.closeConnections()
                        #warning("check this")
                        // maybe setConnected(false)
                        self.logger.error("[sendTCP] Connection cancelled. Restarting...")
                        // restart the connection
                        await self.sendTCP(message: message, completion: completion)
                    }
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
            try startConnection()
        } catch(let error) {
            completion(.failure(error))
            return
        }
    }
    
    /// Sends a DNS request to the server using UDP
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    private func sendUDP(message: DNSMessage, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        do {
            let id = message.header.id
            let data = try message.toData()
            
            logger.trace("[sendUDP] Sending query", metadata: ["host": "\(message.Question[0].QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
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
            connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { responseData, context, isComplete, error in
                do {
                    if let error = error {
                        completion(.failure(DNSError.connectionFailed(error)))
                        return
                    }
                    if let responseData = responseData {
                        self.logger.trace("[sendUDP] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                        
                        let result = try DNSMessage(data: responseData)
                        // check that the id in the response is the same as the one sent in the query
                        if result.header.id != id {
                            self.logger.trace("[sendUDP] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                            completion(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                            return
                        }
                        completion(.success(result))
                    }
                } catch {
                    completion(.failure(DNSError.parsingError(error)))
                }
            }
            
            logger.debug("[sendUDP] Starting connection...")
            connection.start(queue: dnsQueue)
        } catch(let error) {
            completion(.failure(error))
            return
        }
    }
    
    /// Sends a DNS request to the server using HTTPS
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    private func sendHTTPS(message: DNSMessage, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let urlSession = urlSession else {
            completion(.failure(DNSError.connectionTypeMismatch))
            return
        }
        
        guard let url = URL(string: server) else {
            completion(.failure(DNSError.invalidServerAddress))
            return
        }
        
        do {
            let id = message.header.id
            let data = try message.toData()
            
            logger.trace("[sendHTTPS] Sending query", metadata: ["host": "\(message.Question[0].QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
            request.httpBody = data
            
            let task = urlSession.dataTask(with: request, completionHandler: { responseData, response, error in
                guard error == nil, let responseData = responseData else {
                    if let error = error {
                        completion(.failure(DNSError.connectionFailed(error)))
                        return
                    }
                    completion(.failure(DNSError.parsingError(error)))
                    return
                }
                
                do {
                    let status = (response as! HTTPURLResponse).statusCode
                    
                    guard let mimeType = response?.mimeType, mimeType == "application/dns-message" else {
                        throw DNSError.invalidData("Unsuported MIME type in response: '\(response?.mimeType ?? "<nil>")'. Status: \(status)")
                    }
                    
                    guard status == 200 else {
                        throw DNSError.invalidData("HTTPS Status Code is not 200: \(status)")
                    }
                    
                    self.logger.debug("[sendHTTPS] HTTP Response", metadata: ["status": "\(status)", "mime": "\(mimeType)"])
                    self.logger.trace("[sendHTTPS] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                    
                    let result = try DNSMessage(data: responseData)
                    // check that the id in the response is the same as the one sent in the query
                    if result.header.id != id {
                        self.logger.trace("[sendHTTPS] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                        completion(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                        return
                    }
                    completion(.success(result))
                } catch(let error) {
                    completion(.failure(error))
                }
            })
            task.resume()
        } catch(let error) {
            completion(.failure(error))
            return
        }
        
        /*
        let (responseData, response) = try await URLSession.shared.data(for: request)
        let status = (response as! HTTPURLResponse).statusCode
        self.logger.debug("[sendHTTPS] Status: \(status), mime: \(response.mimeType ?? "<nil>")")
        self.logger.trace("[sendHTTPS] Received DNS response: \(responseData.hexEncodedString())")
        // print("[sendHTTPS] response header: \(responseHeader.description())")
        
        return try self.DNSClient.parseDNSResponse(responseData)
         */
    }
    
    /// Parses a domain name in Data
    /// - Parameters:
    ///   - data: The data where the domain is
    ///   - offset: the offset to start parsing the data at
    /// - Returns: The domain parsed and the length (the ammount of bytes consumed). The offset can be increased by the length to know where to continue parsing the data
    public static func parseDomainName(data: Data, offset: Int) throws -> (String, Int) {
        var labels: [String] = []
        var currentOffset = offset
        var consumed = 0

        while currentOffset < data.count {
            let length = Int(data[currentOffset])

            // Null label
            if length == 0 {
                consumed = currentOffset - offset + 1
                // Append an empty string for the trailing dot
                labels.append("")
                break
            }

            // Compressed label (pointer: 11xx xxxx)
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
            
            #warning("Make sure an infinite loop can't happen here")
            if length & 0xC0 == 0xC0 {
                // TODO: handle pointer loops
                if currentOffset + 1 >= data.count {
                    throw DNSError.invalidData("Name pointer over bounds")
                }
                let byte2 = Int(data[currentOffset + 1])
                let pointer = ((length & 0x3F) << 8) | byte2
                
                if currentOffset == pointer {
                    throw DNSError.invalidData("Name pointer references itself")
                }
                
                if pointer > data.count {
                    throw DNSError.invalidData("Name pointer out of bounds")
                }
                
                let (jumpedName, _) = try parseDomainName(data: data, offset: pointer)
                labels.append(jumpedName)
                consumed = currentOffset - offset + 2
                break
            } else {
                let labelStart = currentOffset + 1
                let labelEnd = labelStart + length
                guard labelEnd <= data.count else {
                    throw DNSError.invalidData("End of Name label (\(labelEnd)) over bounds (\(data.count)). offset: \(offset), currentOffset: \(currentOffset)")
                }
                let labelData = data[labelStart..<labelEnd]
                if let label = String(data: labelData, encoding: .utf8) {
                    labels.append(label)
                }
                currentOffset = labelEnd
                consumed = currentOffset - offset
            }
        }
        
        // If there is only one item and it *is* an empty string, add a trailing dot
        return (labels.joined(separator: ".") + (labels.count == 1 && labels.first == "" ? "." : ""), consumed)
    }
}
