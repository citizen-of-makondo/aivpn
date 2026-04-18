import Foundation
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let ioQueue = DispatchQueue(label: "com.aivpn.ios.tunnel.io")
    private let sessionQueue = DispatchQueue(label: "com.aivpn.ios.tunnel.session")

    private var udpConnection: NWConnection?
    private var pathMonitor: NWPathMonitor?

    private var sessionPointer: OpaquePointer?
    private var isStopping = false

    private var keepaliveTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?

    private var currentConnectionKey: String?
    private var lastReceiveAt = Date()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        isStopping = false

        Task {
            do {
                let key = try resolveConnectionKey(options: options)
                currentConnectionKey = key

                let parsed = try parseKeyWithRust(key)
                let session = try createSessionWithRust(key)
                self.sessionPointer = session

                try await applyNetworkSettings(clientIP: parsed.clientIPAddress, remoteAddress: parsed.host)
                try setupUDP(host: parsed.host, port: parsed.port)

                try sendInitPacket()
                startReadLoop()
                startReceiveLoop()
                startKeepaliveLoop()
                startReconnectLoop()
                startPathMonitor()

                completionHandler(nil)
            } catch {
                cleanup()
                completionHandler(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        isStopping = true
        keepaliveTask?.cancel()
        reconnectTask?.cancel()
        keepaliveTask = nil
        reconnectTask = nil

        pathMonitor?.cancel()
        pathMonitor = nil

        udpConnection?.cancel()
        udpConnection = nil

        sessionQueue.sync {
            if let sessionPointer {
                aivpn_session_free(sessionPointer)
                self.sessionPointer = nil
            }
        }

        completionHandler()
    }

    private func cleanup() {
        isStopping = true
        keepaliveTask?.cancel()
        reconnectTask?.cancel()
        keepaliveTask = nil
        reconnectTask = nil

        pathMonitor?.cancel()
        pathMonitor = nil

        udpConnection?.cancel()
        udpConnection = nil

        sessionQueue.sync {
            if let sessionPointer {
                aivpn_session_free(sessionPointer)
                self.sessionPointer = nil
            }
        }
    }

    private func resolveConnectionKey(options: [String: NSObject]?) throws -> String {
        if let raw = options?["connectionKey"] as? String, !raw.isEmpty {
            return raw
        }

        if let raw = options?["connectionKey"] as? NSString {
            let value = raw as String
            if !value.isEmpty {
                return value
            }
        }

        if let protocolConfig = protocolConfiguration as? NETunnelProviderProtocol,
           let raw = protocolConfig.providerConfiguration?["connectionKey"] as? String,
           !raw.isEmpty {
            return raw
        }

        throw TunnelError.missingConnectionKey
    }

    private func applyNetworkSettings(clientIP: String, remoteAddress: String) async throws {
        let ipv4 = NEIPv4Settings(addresses: [clientIP], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.ipv4Settings = ipv4
        settings.dnsSettings = dns
        settings.mtu = 1340 as NSNumber

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            setTunnelNetworkSettings(settings) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func setupUDP(host: String, port: UInt16) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw TunnelError.invalidServerEndpoint
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                NSLog("[AIVPN] UDP ready")
            case .failed(let error):
                NSLog("[AIVPN] UDP failed: \(error.localizedDescription)")
            case .waiting(let error):
                NSLog("[AIVPN] UDP waiting: \(error.localizedDescription)")
            default:
                break
            }
        }
        connection.start(queue: ioQueue)

        self.udpConnection = connection
    }

    private func startReadLoop() {
        guard !isStopping else {
            return
        }

        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else {
                return
            }
            guard !self.isStopping else {
                return
            }

            for packet in packets {
                do {
                    let encrypted = try self.encryptPacket(packet)
                    self.sendDatagram(encrypted)
                } catch {
                    NSLog("[AIVPN] encrypt packet failed: \(error.localizedDescription)")
                }
            }

            self.startReadLoop()
        }
    }

    private func startReceiveLoop() {
        guard !isStopping else {
            return
        }

        udpConnection?.receiveMessage { [weak self] data, _, _, error in
            guard let self else {
                return
            }
            guard !self.isStopping else {
                return
            }

            if let error {
                NSLog("[AIVPN] receive error: \(error.localizedDescription)")
            }

            if let data, !data.isEmpty {
                self.lastReceiveAt = Date()
                self.handleIncomingDatagram(data)
            }

            self.startReceiveLoop()
        }
    }

    private func handleIncomingDatagram(_ datagram: Data) {
        do {
            let decrypted = try decryptPacket(datagram)
            guard !decrypted.isEmpty else {
                return
            }

            let protocolNumber: NSNumber = packetProtocolNumber(for: decrypted)
            packetFlow.writePackets([decrypted], withProtocols: [protocolNumber])
        } catch {
            NSLog("[AIVPN] decrypt packet failed: \(error.localizedDescription)")
        }
    }

    private func packetProtocolNumber(for packet: Data) -> NSNumber {
        guard let first = packet.first else {
            return NSNumber(value: AF_INET)
        }

        let version = (first & 0xF0) >> 4
        if version == 6 {
            return NSNumber(value: AF_INET6)
        }

        return NSNumber(value: AF_INET)
    }

    private func startKeepaliveLoop() {
        keepaliveTask?.cancel()
        keepaliveTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled && !self.isStopping {
                do {
                    try await Task.sleep(for: .seconds(15))
                    let packet = try self.buildKeepalivePacket()
                    self.sendDatagram(packet)
                } catch {
                    if !Task.isCancelled {
                        NSLog("[AIVPN] keepalive failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    private func startReconnectLoop() {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled && !self.isStopping {
                try? await Task.sleep(for: .seconds(12))
                if self.isStopping {
                    return
                }

                let silence = Date().timeIntervalSince(self.lastReceiveAt)
                if silence > 45 {
                    do {
                        let initPacket = try self.buildInitPacket()
                        self.sendDatagram(initPacket)
                    } catch {
                        NSLog("[AIVPN] reconnect init failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            guard !self.isStopping else { return }
            if path.status == .satisfied {
                do {
                    let initPacket = try self.buildInitPacket()
                    self.sendDatagram(initPacket)
                } catch {
                    NSLog("[AIVPN] path-change init failed: \(error.localizedDescription)")
                }
            }
        }
        monitor.start(queue: ioQueue)
        pathMonitor = monitor
    }

    private func sendInitPacket() throws {
        let initPacket = try buildInitPacket()
        sendDatagram(initPacket)
    }

    private func sendDatagram(_ data: Data) {
        guard !isStopping else {
            return
        }

        udpConnection?.send(content: data, completion: .contentProcessed { error in
            if let error {
                NSLog("[AIVPN] UDP send error: \(error.localizedDescription)")
            }
        })
    }

    private func buildInitPacket() throws -> Data {
        try sessionQueue.sync {
            guard let sessionPointer else {
                throw TunnelError.sessionUnavailable
            }

            var outPacket = AivpnBytes()
            var errorPointer: UnsafeMutablePointer<CChar>? = nil

            let status = aivpn_session_build_init(sessionPointer, &outPacket, &errorPointer)
            defer {
                aivpn_bytes_free(&outPacket)
                if let errorPointer {
                    aivpn_error_free(errorPointer)
                }
            }

            guard status == Int32(AIVPN_OK) else {
                throw TunnelError.rustError(cString(errorPointer) ?? "build init failed with code \(status)")
            }

            return dataFromBytes(outPacket)
        }
    }

    private func buildKeepalivePacket() throws -> Data {
        try sessionQueue.sync {
            guard let sessionPointer else {
                throw TunnelError.sessionUnavailable
            }

            var outPacket = AivpnBytes()
            var errorPointer: UnsafeMutablePointer<CChar>? = nil

            let status = aivpn_session_build_keepalive(sessionPointer, &outPacket, &errorPointer)
            defer {
                aivpn_bytes_free(&outPacket)
                if let errorPointer {
                    aivpn_error_free(errorPointer)
                }
            }

            guard status == Int32(AIVPN_OK) else {
                throw TunnelError.rustError(cString(errorPointer) ?? "build keepalive failed with code \(status)")
            }

            return dataFromBytes(outPacket)
        }
    }

    private func encryptPacket(_ packet: Data) throws -> Data {
        try sessionQueue.sync {
            guard let sessionPointer else {
                throw TunnelError.sessionUnavailable
            }

            var outPacket = AivpnBytes()
            var errorPointer: UnsafeMutablePointer<CChar>? = nil

            let status = packet.withUnsafeBytes { rawBuffer -> Int32 in
                guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return Int32(AIVPN_ERR_INVALID_FORMAT)
                }
                return aivpn_session_encrypt_packet(
                    sessionPointer,
                    baseAddress,
                    rawBuffer.count,
                    &outPacket,
                    &errorPointer
                )
            }

            defer {
                aivpn_bytes_free(&outPacket)
                if let errorPointer {
                    aivpn_error_free(errorPointer)
                }
            }

            guard status == Int32(AIVPN_OK) else {
                throw TunnelError.rustError(cString(errorPointer) ?? "encrypt failed with code \(status)")
            }

            return dataFromBytes(outPacket)
        }
    }

    private func decryptPacket(_ packet: Data) throws -> Data {
        try sessionQueue.sync {
            guard let sessionPointer else {
                throw TunnelError.sessionUnavailable
            }

            var outPacket = AivpnBytes()
            var errorPointer: UnsafeMutablePointer<CChar>? = nil

            let status = packet.withUnsafeBytes { rawBuffer -> Int32 in
                guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return Int32(AIVPN_ERR_INVALID_FORMAT)
                }
                return aivpn_session_decrypt_packet(
                    sessionPointer,
                    baseAddress,
                    rawBuffer.count,
                    &outPacket,
                    &errorPointer
                )
            }

            defer {
                aivpn_bytes_free(&outPacket)
                if let errorPointer {
                    aivpn_error_free(errorPointer)
                }
            }

            guard status == Int32(AIVPN_OK) else {
                throw TunnelError.rustError(cString(errorPointer) ?? "decrypt failed with code \(status)")
            }

            return dataFromBytes(outPacket)
        }
    }

    private func parseKeyWithRust(_ raw: String) throws -> ParsedConnectionKey {
        var parsed = AivpnParsedKey()
        var errorPointer: UnsafeMutablePointer<CChar>? = nil

        let status = raw.withCString { cKey -> Int32 in
            aivpn_parse_key(cKey, &parsed, &errorPointer)
        }

        defer {
            aivpn_parsed_key_free(&parsed)
            if let errorPointer {
                aivpn_error_free(errorPointer)
            }
        }

        guard status == Int32(AIVPN_OK) else {
            throw TunnelError.rustError(cString(errorPointer) ?? "parse failed with code \(status)")
        }

        guard let serverEndpoint = cString(parsed.server),
              let clientIP = cString(parsed.client_ip) else {
            throw TunnelError.invalidConnectionKey
        }

        let endpoint = parseEndpoint(serverEndpoint)
        return ParsedConnectionKey(
            serverEndpoint: serverEndpoint,
            host: endpoint.host,
            port: endpoint.port,
            clientIPAddress: clientIP
        )
    }

    private func createSessionWithRust(_ raw: String) throws -> OpaquePointer {
        var parsed = AivpnParsedKey()
        var errorPointer: UnsafeMutablePointer<CChar>? = nil

        let parseStatus = raw.withCString { cKey -> Int32 in
            aivpn_parse_key(cKey, &parsed, &errorPointer)
        }

        guard parseStatus == Int32(AIVPN_OK) else {
            defer {
                aivpn_parsed_key_free(&parsed)
                if let errorPointer {
                    aivpn_error_free(errorPointer)
                }
            }
            throw TunnelError.rustError(cString(errorPointer) ?? "parse for session failed with code \(parseStatus)")
        }

        if let ptr = errorPointer {
            aivpn_error_free(ptr)
            errorPointer = nil
        }

        let session = aivpn_session_create(&parsed, &errorPointer)
        defer {
            aivpn_parsed_key_free(&parsed)
            if let errorPointer {
                aivpn_error_free(errorPointer)
            }
        }

        guard let session else {
            throw TunnelError.rustError(cString(errorPointer) ?? "session create failed")
        }

        return session
    }

    private func parseEndpoint(_ value: String) -> (host: String, port: UInt16) {
        let endpoint = value.trimmingCharacters(in: .whitespacesAndNewlines)

        if endpoint.hasPrefix("["), let close = endpoint.firstIndex(of: "]") {
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            let tail = endpoint[close...]
            if tail.hasPrefix("]:") {
                let start = endpoint.index(close, offsetBy: 2)
                let port = UInt16(endpoint[start...]) ?? 443
                return (host, port)
            }
            return (host, 443)
        }

        if endpoint.split(separator: ":").count > 2 {
            return (endpoint, 443)
        }

        if let idx = endpoint.lastIndex(of: ":") {
            let host = String(endpoint[..<idx])
            let port = UInt16(endpoint[endpoint.index(after: idx)...]) ?? 443
            return (host, port)
        }

        return (endpoint, 443)
    }

    private func cString(_ value: UnsafePointer<CChar>?) -> String? {
        guard let value else {
            return nil
        }
        return String(cString: value)
    }

    private func dataFromBytes(_ bytes: AivpnBytes) -> Data {
        guard let ptr = bytes.ptr, bytes.len > 0 else {
            return Data()
        }
        return Data(bytes: ptr, count: bytes.len)
    }
}

private struct ParsedConnectionKey {
    let serverEndpoint: String
    let host: String
    let port: UInt16
    let clientIPAddress: String
}

enum TunnelError: LocalizedError {
    case missingConnectionKey
    case invalidConnectionKey
    case invalidServerEndpoint
    case sessionUnavailable
    case rustError(String)

    var errorDescription: String? {
        switch self {
        case .missingConnectionKey:
            return "Connection key was not passed to tunnel extension"
        case .invalidConnectionKey:
            return "Connection key is invalid"
        case .invalidServerEndpoint:
            return "Server endpoint is invalid"
        case .sessionUnavailable:
            return "Rust session is unavailable"
        case .rustError(let message):
            return message
        }
    }
}
