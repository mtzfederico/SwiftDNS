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
public enum DNSConnectionType: Sendable {
    case dnsOverTLS
    case dnsOverHTTPS
    case dnsOverUDP
    case dnsOverTCP
    
    /// Describes the connection type in a short string
    /// - Returns: A short string with no spaces that describes the connection type
    public func displayName() -> String {
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
    
    private var isConnected: Bool = false
    
    /// DNSClass Initialiser
    /// - Parameters:
    ///   - server: The server to send the query to. For UDP and TCP, it can be an IP or a domain. For TLS it should be a domain name (Ex: "dns.quad9.net" or "one.one.one.one"), and for HTTPS it sould be a URL (Ex: "https://cloudflare-dns.com/dns-query" or "https://dns.quad9.net/dns-query")
    ///   - connectionType: The DNS conecction type to use. UDP, TCP, TLS, or HTTPS
    ///   - logger: The logger used
    public init(server: String, connectionType: DNSConnectionType, logger: Logger = Logger(label: "com.mtzfederico.SwiftDNS")) {
        self.dnsQueue = DispatchQueue(label: "DNSClient-\(server.replacingOccurrences(of: " ", with: "_"))_\(connectionType.displayName())", attributes: .concurrent)
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
            self.connection = nil
        }
    }
    
    deinit {
        Task { [self] in
            await self.closeConnections()
        }
    }
    
    private func startConnection() async throws {
        #warning("Implement me")
        // use this to start the connection
        // keep isConnected state, call it when sending a request.
        // if not connected, connect. On connection failure restart the connection
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
    public func query(host: String, type: DNSRecordType, Class: DNSClass) async throws -> DNSMessage {
        return try await withCheckedThrowingContinuation { continuation in
            self.query(host: host, type: type, Class: Class, completion: { result in
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
    public func query(host: String, type: DNSRecordType, Class: DNSClass, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        if host.isEmpty || !host.isDNSSafe {
            completion(.failure(DNSError.invalidDomainName))
            return
        }
        
        let question = QuestionSection(host: host, type: type, CLASS: Class)
        
        switch connectionType {
        case .dnsOverTLS, .dnsOverTCP:
            return sendTCP(question: question, completion: completion)
        case .dnsOverUDP:
            return sendUDP(question: question, completion: completion)
        case .dnsOverHTTPS:
            return sendHTTPS(question: question, completion: completion)
        }
    }
    
    /// Closes all connections  gracefully.
    public func closeConnections() {
        self.connection?.cancel()
        setConnected(false)
    }
    
    /// Sends a DNS request to the server using TCP
    /// - Parameters:
    ///   - host: The host to query, the QNAME.
    ///   - type: The DNS recoord type to query for
    ///   - Class: The class to query
    ///   - completion: The DNS response or an Error
    private func sendTCP(question: QuestionSection, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        do {
            let (query, id) = try DNSClient.encodeQuery(question: question)
            
            
            // TCP has a 2-byte prefix with the length because it is a stram of data and it needs to know how long all of it is
            // In UDP, the whole packet is a single request. In TCP (and TLS) the data can go over multiple packets/frames
            let lengthPrefix = UInt16(query.count)
            
            let data: Data = Data(withUnsafeBytes(of: lengthPrefix.bigEndian, Array.init)) + query
            
            logger.trace("[sendTCP] Sending query", metadata: ["host": "\(question.QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
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
                            connection.cancel()
                            Task {
                                await self.setConnected(false)
                            }
                            
                            self.logger.error("[sendTCP] Connection failed. Restarting...",  metadata: ["error": "\(error.localizedDescription)"])
                            // restart the connection
                            self.sendTCP(question: question, completion: completion)
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
                                    let result = try DNSClient.parseDNSResponse(data)
                                    // check that the id in the response is the same as the one sent in the query
                                    if result.header.id != id {
                                        self.logger.trace("[sendTCP] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                                        completion(.failure(DNSError.IDMismatch))
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
                    // _Concurrency/CheckedContinuation.swift:196: Fatal error: SWIFT TASK CONTINUATION MISUSE: query(host:type:Class:) tried to resume its continuation more than once, throwing connectionFailed(POSIXErrorCode(rawValue: 54): Connection reset by peer)!
                    
                    // if error  == POSIXErrorCode(rawValue: 54) { }
                    
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
            connection.start(queue: dnsQueue)
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
    private func sendUDP(question: QuestionSection, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let connection = self.connection else {
            completion(.failure(DNSError.connectionIsNil))
            return
        }
        
        /*
         let id = UInt16.random(in: 0...UInt16.max)
         let flags = DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
         
         // print((String(format:"%02x", flags.toRaw())))
         
         let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0).toData()
         let question = QuestionSection(host: host, type: type, CLASS: Class).toData()
         
         let data: Data = header + question
         */
        
        do {
            
            let (data, id) = try DNSClient.encodeQuery(question: question)
            
            logger.trace("[sendUDP] Sending query", metadata: ["host": "\(question.QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
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
                        
                        let result = try DNSClient.parseDNSResponse(responseData)
                        // check that the id in the response is the same as the one sent in the query
                        if result.header.id != id {
                            self.logger.trace("[sendUDP] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                            completion(.failure(DNSError.IDMismatch))
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
    private func sendHTTPS(question: QuestionSection, completion: @escaping @Sendable (sending Result<DNSMessage, Error>) -> ()) {
        guard let url = URL(string: server) else {
            completion(.failure(DNSError.invalidServerAddress))
            return
        }
        
        do {
            
            let (data, id) = try DNSClient.encodeQuery(question: question)
            
            logger.trace("[sendHTTPS] Sending query", metadata: ["host": "\(question.QNAME)", "id": "0x\(String(format:"%02x", id))", "Data": "\(data.hexEncodedString())"])
            
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
                    self.logger.trace("[sendHTTPS] Received DNS response", metadata: ["data": "\(responseData.hexEncodedString())"])
                    
                    let result = try DNSClient.parseDNSResponse(responseData)
                    // check that the id in the response is the same as the one sent in the query
                    if result.header.id != id {
                        self.logger.trace("[sendHTTPS] ID Mismatch", metadata: ["sent": "0x\(String(format:"%02x", id))", "received": "0x\(String(format:"%02x", result.header.id))"])
                        completion(.failure(DNSError.IDMismatch))
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
    
    /// Retuns Data for the query and the ID
    /// - Parameter question: The question to encode to Data
    /// - Returns: The header and query as Data and the id generated for the query
    public static func encodeQuery(question: QuestionSection) throws -> (Data, UInt16) {
        let id = UInt16.random(in: 0...UInt16.max)
        let flags = try DNSHeader.DNSFlags(qr: 0, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 0, rcode: 0)
        
        // print((String(format:"%02x", flags.toRaw())))
        
        let header = DNSHeader(id: id, flags: flags, QDCOUNT: 1, ANCOUNT: 0, NSCOUNT: 0, ARCOUNT: 0).toData()
        // let question = QuestionSection(host: host, type: type, CLASS: .internet).toData()
        
        let data: Data = header + question.toData()
        return (data, id)
    }
    
    /// Parses a domain name in Data
    /// - Parameters:
    ///   - data: The data where the domain is
    ///   - offset: the offset to start parsing the data at
    /// - Returns: The domain parsed and the length. The offset can be increased by the length to keep parsing the data
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
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
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
    
    /// Encodes a domain name
    /// - Parameter name: The domain name to encode
    /// - Returns: The domaiin name encoded
    public static func encodeDomainName(name: String) -> Data {
        // labels          63 octets or less
        // names           255 octets or less
        //
        // 4.1.4. Message compression:
        // In compression, the first two bits are ones.  This allows a pointer to be distinguished
        // from a label, since the label must begin with two zero bits because
        // labels are restricted to 63 octets or less.  (The 10 and 01 combinations
        // are reserved for future use.)
        
        var bytes = Data()
        
        let labels = name.split(separator: ".")
        for label in labels {
            let length = UInt8(label.count)
            bytes.append(length)
            bytes.append(contentsOf: label.utf8)
        }
        
        bytes.append(0) // End of domain name
        return bytes
    }
    
    /// Parses a DNS response
    /// - Parameter data: The data representing the DNS response
    /// - Returns: The parsed DNS response
    public static func parseDNSResponse(_ data: Data) throws -> DNSMessage {
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
            // if rr.type == .OPT {
                // append to edns yaddee yadda
            // }
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
        
        return DNSMessage(header: header, Question: questions, Answer: answers, Authority: authority, Additional: additional)
    }
}
