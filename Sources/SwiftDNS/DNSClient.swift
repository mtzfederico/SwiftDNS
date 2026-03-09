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
        case .dnsOverTLS:   return "DoT"
        case .dnsOverHTTPS: return "DoH"
        case .dnsOverUDP:   return "DoUDP"
        case .dnsOverTCP:   return "DoTCP"
        }
    }
}

/// The DNS Client used to send DNS queries
///
/// Initialize it with the server's IP or hostname and the connection type and use the Query method to send DNS queries.
final public actor DNSClient: Sendable {
    private let dnsQueue: DispatchQueue
    /// The logger used
    private let logger: Logger
    /// The NWConnection used to send UDP, TCP, and TLS queries. HTTP queries use URLSession.shared.
    /// Declared as var so it can be recreated after cancellation (e.g. after a failed retry).
    private var connection: NWConnection?
    /// The connection type used to send the request
    private let connectionType: DNSConnectionType
    /// The server used to send the query to
    private let server: String
    /// The URL Session used when sending queries over HTTPS
    private var urlSession: URLSession?
    /// Indicates whether the connection is connected to a server or not
    ///
    /// Only set to true when the .ready state fires, because start() is asynchronous and the connection may not be usable immediately.
    private var isConnected: Bool = false
    /// Maximum number of times sendTCP/sendUDP will retry on transient connection errors
    private let maxRetries: Int = 3
    /// Pending queries waiting to be sent once the current in-flight query completes.
    ///
    /// This prevents concurrent queries from overwriting each other's stateUpdateHandler and racing on connection.receive().
    /// HTTPS queries bypass this queue entirely since URLSession handles concurrency on its own.
    private var pendingQueries: [(DNSMessage, @Sendable (Result<DNSMessage, Error>) -> Void)] = []
    /// True while a TCP or UDP query is currently in-flight on the shared NWConnection
    private var isQueryInFlight: Bool = false
    
    // MARK: - Init
    
    /// DNSClass Initialiser
    /// - Parameters:
    ///   - server: The server to send the query to. For UDP and TCP, it can be an IP or a domain.
    ///     For TLS it should be a domain name (Ex: "dns.quad9.net" or "one.one.one.one"),
    ///     and for HTTPS it should be a URL (Ex: "https://cloudflare-dns.com/dns-query")
    ///   - connectionType: The DNS connection type to use: UDP, TCP, TLS, or HTTPS
    ///   - urlSession: An optional URLSession for DoH. Ignored for other connection types.
    ///   - logger: The logger used
    public init(server: String, connectionType: DNSConnectionType, urlSession: URLSession? = nil, logger: Logger = Logger(label: "com.mtzfederico.SwiftDNS")) {
        self.dnsQueue = DispatchQueue(label: "DNSClient-\(server.replacingOccurrences(of: " ", with: "_"))_\(connectionType.description)", attributes: .concurrent)
        self.logger = logger
        self.server = server
        self.connectionType = connectionType
        
        switch connectionType {
        case .dnsOverTLS:
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
    
    // MARK: - Connection state
    
    private func setConnected(_ value: Bool) {
        self.isConnected = value
    }
    
    /// Creates a fresh NWConnection for the current server and connectionType.
    /// Called by closeConnections() so the next startConnection() has a usable connection.
    /// NWConnection cannot be restarted once cancelled, so a new one must be created.
    private func makeConnection() -> NWConnection {
        switch connectionType {
        case .dnsOverTLS:
            let parameters = NWParameters.tls
            parameters.serviceClass = .responsiveData
            parameters.expiredDNSBehavior = .allow
            return NWConnection(to: .hostPort(host: .name(server, nil), port: 853), using: parameters)
        case .dnsOverUDP:
            return NWConnection(host: .name(server, nil), port: 53, using: .udp)
        case .dnsOverTCP:
            return NWConnection(host: .name(server, nil), port: 53, using: .tcp)
        case .dnsOverHTTPS:
            // Should never be called for HTTPS since connection is nil for that type
            fatalError("makeConnection() should not be called for dnsOverHTTPS")
        }
    }
    
    // MARK: - Public query API
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - EDNS: An opptional EDNSMessage to send
    /// - Returns: The DNS response
    @available(macOS 10.15, iOS 13.0, *)
    public func query(host: String, type: DNSRecordType, Class: DNSClass = .internet, EDNS: EDNSMessage? = nil) async throws -> DNSMessage {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(host: host, type: type, Class: Class, EDNS: EDNS) { result in
                continuation.resume(with: result)
            }
        }
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameter message: The DNS Message to send
    /// - Returns: The DNS response
    @available(macOS 10.15, iOS 13.0, *)
    public func query(message: DNSMessage) async throws -> DNSMessage {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(message: message) { result in
                continuation.resume(with: result)
            }
        }
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - EDNS: An opptional EDNSMessage to send
    ///   - completion: The DNS response or an Error
    public func query(host: String, type: DNSRecordType, Class: DNSClass = .internet, EDNS: EDNSMessage? = nil, completion: @escaping @Sendable (Result<DNSMessage, Error>) -> ()) {
        do {
            guard !host.isEmpty, host.isDNSSafe else {
                completion(.failure(DNSError.invalidDomainName))
                return
            }
            
            let id = UInt16.random(in: 0...UInt16.max)
            let flags = try DNSHeader.DNSFlags(qr: false, opcode: 0, aa: false, tc: false, rd: true, ra: false, rcode: 0)
            let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: EDNS != nil ? 1 : 0)
            
            let question = QuestionSection(host: host, type: type, CLASS: Class)
            let message = DNSMessage(header: header, Question: [question], Answer: [], Authority: [], Additional: [], EDNSData: EDNS)
            query(message: message, completion: completion)
        } catch(let error) {
            completion(.failure(error))
        }
    }
    
    /// Sends a DNS request to the server using the connection type of the DNSClient
    /// - Parameters:
    ///   - message: The DNS Message to send
    ///   - completion: The DNS response or an Error
    public func query(message: DNSMessage, completion: @escaping @Sendable (Result<DNSMessage, Error>) -> ()) {
        switch connectionType {
        case .dnsOverTLS, .dnsOverTCP, .dnsOverUDP:
            // Use the serialization queue so concurrent callers don't overwrite each other's stateUpdateHandler or race on receive()
            enqueueQuery(message: message, completion: completion)
        case .dnsOverHTTPS:
            // HTTPS uses URLSession which handles concurrency internally
            sendHTTPS(message: message, completion: completion)
        }
    }
    
    // MARK: - Query serialization queue
    
    /// Enqueues a query and dispatches it immediately if no other query is in-flight.
    /// If a query is already running on the shared NWConnection, the new query is
    /// held in pendingQueries until the current one completes.
    private func enqueueQuery(message: DNSMessage, completion: @escaping @Sendable (Result<DNSMessage, Error>) -> Void) {
        if isQueryInFlight {
            logger.debug("[enqueueQuery] Query in-flight, queuing. Pending: \(pendingQueries.count + 1)")
            pendingQueries.append((message, completion))
            return
        }
        dispatchQuery(message: message, completion: completion)
    }
    
    /// Marks a query as in-flight and dispatches it to the appropriate send function.
    private func dispatchQuery(message: DNSMessage, completion: @escaping @Sendable (Result<DNSMessage, Error>) -> Void) {
        isQueryInFlight = true
        
        // Wrap the completion so that when it finishes, the next pending query is dispatched
        let wrappedCompletion: @Sendable (Result<DNSMessage, Error>) -> Void = { [weak self] result in
            completion(result)
            Task { await self?.dequeueNextQuery() }
        }
        
        switch connectionType {
        case .dnsOverTLS, .dnsOverTCP:
            sendTCP(message: message, retryCount: 0, completion: wrappedCompletion)
        case .dnsOverUDP:
            sendUDP(message: message, retryCount: 0, completion: wrappedCompletion)
        case .dnsOverHTTPS:
            // Should not be reached. HTTPS bypasses the queue in query(message:completion:)
            completion(.failure(DNSError.connectionTypeMismatch))
        }
    }
    
    /// Called when a query completes. Dispatches the next pending query, if any.
    private func dequeueNextQuery() {
        isQueryInFlight = false
        guard !pendingQueries.isEmpty else { return }
        let (message, completion) = pendingQueries.removeFirst()
        logger.debug("[dequeueNextQuery] Dispatching next query. Remaining: \(pendingQueries.count)")
        dispatchQuery(message: message, completion: completion)
    }
    
    // MARK: - helper functions
    
    /// Starts the NWConnection if it isn't already running.
    private func startConnection() throws {
        guard !isConnected else {
            logger.trace("[startConnection] Connection already started")
            return
        }
        
        guard let connection else { throw DNSError.connectionIsNil }
        connection.start(queue: dnsQueue)
    }
    
    /// Closes the current connection gracefully and optionally creates a new NWConnection ready for the next attempt.
    ///
    /// A cancelled NWConnection cannot be restarted, so a new one must be created here.
    /// - Parameter createNewConnection: When true, creates a new NWConnection for the next connection attempt
    public func closeConnections(createNewConnection: Bool = false) {
        logger.trace("Closing Connection")
        connection?.cancel()
        if createNewConnection {
            // Replace the cancelled connection with a fresh one so the next startConnection() call works
            connection = makeConnection()
        }
        setConnected(false)
    }
    
    // MARK: - TCP / TLS
    
    /// Sends a DNS request to the server using TCP or TLS
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    private func sendTCP(message: DNSMessage, retryCount: Int, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        do {
            let id = message.header.id
            let query = try message.toData()
            
            // TCP has a 2-byte prefix with the length because it is a stream of data and it needs to know how long all of it is
            // In UDP, the whole packet is a single request. In TCP (and TLS) the data can go over multiple packets/frames
            let length = UInt16(query.count)
            let data: Data = Data(withUnsafeBytes(of: length.bigEndian, Array.init)) + query
            
            logger.trace("[sendTCP] Sending query", metadata: [
                "host": "\(message.Question[0].QNAME)",
                "id": "0x\(String(format:"%02x", id))",
                "data": "\(data.hexEncodedString())"
            ])
            
            /// Clears the handler and calls completion exactly once.
            @Sendable func finish(_ result: Result<DNSMessage, Error>) {
                connection.stateUpdateHandler = nil
                completion(result)
            }
            
            /// Retries up to maxRetries times, then fails.
            @Sendable func retryOrFail(reason: String, error: Error) {
                if retryCount < maxRetries {
                    logger.error("[sendTCP: retryOrFail] \(reason). Retrying (\(retryCount + 1)/\(maxRetries))", metadata: ["error": "\(error.localizedDescription)"])
                    Task {
                        await self.closeConnections(createNewConnection: true)
                        await self.sendTCP(message: message, retryCount: retryCount + 1, completion: completion)
                    }
                } else {
                    logger.error("[sendTCP: retryOrFail] \(reason). Max retries reached.", metadata: ["error": "\(error.localizedDescription)"])
                    finish(.failure(error))
                }
            }
            
            // Set handler before calling startConnection().
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    // Only set isConnected after the connection is confirmed usable
                    Task { await self.setConnected(true) }
                    self.logger.debug("[sendTCP] Connection ready, sending data...")
                    
                    connection.send(content: data, completion: .contentProcessed { sendError in
                        if let sendError {
                            retryOrFail(reason: "Send failed", error: DNSError.connectionFailed(sendError))
                            return
                        }
                        
                        // Get the 2-byte length prefix first
                        connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { lengthData, _, _, recvError in
                            if let recvError {
                                finish(.failure(DNSError.connectionFailed(recvError)))
                                return
                            }
                            guard let lengthData, lengthData.count == 2 else {
                                finish(.failure(DNSError.invalidData("Failed to parse response length prefix")))
                                return
                            }
                            
                            let responseLength = Int(lengthData.withUnsafeBytes { $0.load(as: UInt16.self).bigEndian })
                            
                            // Get the actual data
                            connection.receive(minimumIncompleteLength: responseLength, maximumLength: responseLength) { responseData, _, _, recvError2 in
                                if let recvError2 {
                                    finish(.failure(DNSError.connectionFailed(recvError2)))
                                    return
                                }
                                guard let responseData else {
                                    finish(.failure(DNSError.invalidData("Response body is empty")))
                                    return
                                }
                                
                                self.logger.trace("[sendTCP] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                                
                                do {
                                    let result = try DNSMessage(data: responseData)
                                    guard result.header.id == id else {
                                        self.logger.trace("[sendTCP] ID mismatch", metadata: [
                                            "sent": "0x\(String(format:"%02x", id))",
                                            "received": "0x\(String(format:"%02x", result.header.id))"
                                        ])
                                        finish(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                                        return
                                    }
                                    finish(.success(result))
                                } catch {
                                    finish(.failure(error))
                                }
                            }
                        }
                    })
                    
                case .failed(let error):
                    retryOrFail(reason: "Connection failed", error: DNSError.connectionFailed(error))
                case .cancelled:
                    // Cancelled is triggered by closeConnections(). no extra action needed.
                    self.logger.debug("[sendTCP] Connection cancelled.")
                case .waiting(let error):
                    self.logger.info("[sendTCP] Connection waiting", metadata: ["error": "\(error.localizedDescription)"])
                case .preparing:
                    self.logger.debug("[sendTCP] Connection preparing...")
                default:
                    finish(.failure(DNSError.unknownState(state)))
                }
            }
            
            logger.debug("[sendTCP] Starting connection...")
            try startConnection()
        } catch(let error) {
            completion(.failure(error))
        }
    }
    
    // MARK: - UDP
    
    /// Sends a DNS request to the server using UDP
    /// - Parameters:
    ///   - message: The DNSMessage to send to the server
    ///   - retryCount: The number of times to try again
    ///   - completion: The DNS response or an Error
    private func sendUDP(message: DNSMessage, retryCount: Int, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        do {
            let id = message.header.id
            let data = try message.toData()
            
            logger.trace("[sendUDP] Sending query", metadata: [
                "host": "\(message.Question[0].QNAME)",
                "id": "0x\(String(format:"%02x", id))",
                "data": "\(data.hexEncodedString())"
            ])
            
            /// Clears the handler and calls completion exactly once.
            @Sendable func finish(_ result: Result<DNSMessage, Error>) {
                connection.stateUpdateHandler = nil
                completion(result)
            }
            
            /// Retries up to maxRetries times, then fails.
            @Sendable func retryOrFail(reason: String, error: Error) {
                if retryCount < maxRetries {
                    logger.error("[sendUDP: retryOrFail] \(reason). Retrying (\(retryCount + 1)/\(maxRetries))", metadata: ["error": "\(error.localizedDescription)"])
                    Task {
                        await self.closeConnections(createNewConnection: true)
                        await self.sendUDP(message: message, retryCount: retryCount + 1, completion: completion)
                    }
                } else {
                    logger.error("[sendUDP: retryOrFail] \(reason). Max retries reached.", metadata: ["error": "\(error.localizedDescription)"])
                    finish(.failure(error))
                }
            }
            
            // Set handler before calling startConnection()
            connection.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    // Only set isConnected after the connection is confirmed usable
                    Task { await self.setConnected(true) }
                    self.logger.debug("[sendUDP] Connection ready, sending data...")
                    
                    connection.send(content: data, completion: .contentProcessed { sendError in
                        if let sendError {
                            retryOrFail(reason: "Send failed", error: DNSError.connectionFailed(sendError))
                            return
                        }
                        
                        // Only call receive after send succeeds
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { responseData, _, _, recvError in
                            if let recvError {
                                finish(.failure(DNSError.connectionFailed(recvError)))
                                return
                            }
                            guard let responseData else {
                                finish(.failure(DNSError.noDataReceived))
                                return
                            }
                            
                            self.logger.trace("[sendUDP] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                            do {
                                let result = try DNSMessage(data: responseData)
                                
                                guard result.header.id == id else {
                                    self.logger.trace("[sendUDP] ID mismatch", metadata: [
                                        "sent": "0x\(String(format:"%02x", id))",
                                        "received": "0x\(String(format:"%02x", result.header.id))"
                                    ])
                                    finish(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                                    return
                                }
                                
                                // Detect truncated responses (TC bit). tc is true/1 when the response was truncated.
                                if result.header.flags.tc {
                                    finish(.failure(DNSError.responseTruncated))
                                    return
                                }
                                
                                finish(.success(result))
                            } catch(let error) {
                                finish(.failure(DNSError.parsingError(error)))
                            }
                        }
                    })
                    
                case .failed(let error):
                    retryOrFail(reason: "Connection failed", error: DNSError.connectionFailed(error))
                case .waiting(let error):
                    self.logger.info("[sendUDP] Connection waiting", metadata: ["error": "\(error.localizedDescription)"])
                case .preparing:
                    self.logger.debug("[sendUDP] Connection preparing...")
                default:
                    finish(.failure(DNSError.unknownState(state)))
                }
            }
            
            logger.debug("[sendUDP] Starting connection...")
            // Use startConnection() to avoid calling start() on an already-running connection
            try startConnection()
        } catch(let error) {
            completion(.failure(error))
        }
    }
    
    // MARK: - HTTPS
    
    /// Sends a DNS request to the server using HTTPS
    /// - Parameters:
    ///   - message: The DNSMessage to send to the server
    ///   - completion: The DNS response or an Error
    private func sendHTTPS(message: DNSMessage, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let urlSession else {
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
            
            logger.trace("[sendHTTPS] Sending query", metadata: [
                "host": "\(message.Question[0].QNAME)",
                "id": "0x\(String(format:"%02x", id))",
                "data": "\(data.hexEncodedString())"
            ])
            
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
            request.httpBody = data
            
            let task = urlSession.dataTask(with: request) { responseData, response, error in
                guard error == nil, let responseData else {
                    completion(.failure(error.map { DNSError.connectionFailed($0) } ?? DNSError.noDataReceived))
                    return
                }
                
                do {
                    let httpResponse = response as! HTTPURLResponse
                    let status = httpResponse.statusCode
                    
                    guard let mimeType = response?.mimeType, mimeType == "application/dns-message" else {
                        throw DNSError.invalidData("Unsupported MIME type: '\(response?.mimeType ?? "<nil>")'. Status: \(status)")
                    }
                    
                    guard status == 200 else {
                        throw DNSError.invalidData("HTTPS status is not 200: \(status)")
                    }
                    
                    self.logger.debug("[sendHTTPS] HTTP Response", metadata: ["status": "\(status)", "mime": "\(mimeType)"])
                    self.logger.trace("[sendHTTPS] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                    
                    let result = try DNSMessage(data: responseData)
                    // check that the id in the response is the same as the one sent in the query
                    guard result.header.id == id else {
                        self.logger.trace("[sendHTTPS] ID mismatch", metadata: [
                            "sent": "0x\(String(format:"%02x", id))",
                            "received": "0x\(String(format:"%02x", result.header.id))"
                        ])
                        completion(.failure(DNSError.IDMismatch(got: result.header.id, expected: id)))
                        return
                    }
                    completion(.success(result))
                } catch(let error) {
                    completion(.failure(error))
                }
            }
            task.resume()
        } catch(let error) {
            completion(.failure(error))
        }
    }
}
