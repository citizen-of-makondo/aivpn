import Foundation

struct AIVPNConnectionKey: Equatable {
    static let schemePrefix = "aivpn://"

    let serverEndpoint: String
    let serverPublicKeyBase64: String
    let preSharedKeyBase64: String?
    let clientIPAddress: String

    var host: String {
        let endpoint = serverEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]") else { return endpoint }
            return String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
        }

        if endpoint.split(separator: ":").count > 2 {
            return endpoint
        }

        if let idx = endpoint.lastIndex(of: ":") {
            return String(endpoint[..<idx])
        }
        return endpoint
    }

    var port: Int {
        let endpoint = serverEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]") else { return 443 }
            let suffix = endpoint[close...]
            if suffix.hasPrefix("]:") {
                let start = endpoint.index(close, offsetBy: 2)
                return Int(endpoint[start...]) ?? 443
            }
            return 443
        }

        if endpoint.split(separator: ":").count > 2 {
            return 443
        }

        guard let idx = endpoint.lastIndex(of: ":") else {
            return 443
        }
        return Int(endpoint[endpoint.index(after: idx)...]) ?? 443
    }

    var rawValue: String {
        let payload = Payload(
            s: serverEndpoint,
            k: serverPublicKeyBase64,
            p: preSharedKeyBase64,
            i: clientIPAddress
        )
        let data = try? JSONEncoder().encode(payload)
        let encoded = data?.base64URLEncodedString() ?? ""
        return "\(Self.schemePrefix)\(encoded)"
    }

    static func parse(_ raw: String) throws -> AIVPNConnectionKey {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw AIVPNKeyParseError.emptyPayload
        }

        if !trimmed.hasPrefix(Self.schemePrefix) {
            throw AIVPNKeyParseError.invalidPrefix
        }

        return try AIVPNRustBridge.parseKey(trimmed)
    }
}

enum AIVPNKeyParseError: Error, LocalizedError, Equatable {
    case invalidPrefix
    case emptyPayload
    case rustError(String)
    case invalidServer
    case missingSharedKey
    case missingClientID

    var errorDescription: String? {
        switch self {
        case .invalidPrefix:
            return "Key must start with aivpn://"
        case .emptyPayload:
            return "Connection key is required"
        case .rustError(let message):
            return message
        case .invalidServer:
            return "Server endpoint is invalid"
        case .missingSharedKey:
            return "Server public key (k) is required"
        case .missingClientID:
            return "Client IP (i) is required"
        }
    }
}

private struct Payload: Codable, Equatable {
    let s: String
    let k: String
    let p: String?
    let i: String
}

enum AIVPNRustBridge {
    static func parseKey(_ raw: String) throws -> AIVPNConnectionKey {
        var parsed = AivpnParsedKey()
        var errorPointer: UnsafeMutablePointer<CChar>? = nil

        let status = raw.withCString { cString -> Int32 in
            aivpn_parse_key(cString, &parsed, &errorPointer)
        }

        defer {
            aivpn_parsed_key_free(&parsed)
            if let errorPointer {
                aivpn_error_free(errorPointer)
            }
        }

        guard status == Int32(AIVPN_OK) else {
            throw AIVPNKeyParseError.rustError(cString(errorPointer) ?? "Rust parse failed with code \(status)")
        }

        guard let server = cString(parsed.server), !server.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AIVPNKeyParseError.invalidServer
        }

        guard let serverKey = cString(parsed.server_key_b64), !serverKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AIVPNKeyParseError.missingSharedKey
        }

        guard let clientID = cString(parsed.client_ip), !clientID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw AIVPNKeyParseError.missingClientID
        }

        let psk = cString(parsed.psk_b64)?.trimmingCharacters(in: .whitespacesAndNewlines)

        return AIVPNConnectionKey(
            serverEndpoint: server.trimmingCharacters(in: .whitespacesAndNewlines),
            serverPublicKeyBase64: serverKey.trimmingCharacters(in: .whitespacesAndNewlines),
            preSharedKeyBase64: psk?.isEmpty == true ? nil : psk,
            clientIPAddress: clientID.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    static func cString(_ value: UnsafePointer<CChar>?) -> String? {
        guard let value else {
            return nil
        }
        return String(cString: value)
    }
}

private extension Data {
    init?(base64URLEncoded input: String) {
        var base64 = input.replacingOccurrences(of: "-", with: "+")
        base64 = base64.replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        if padding > 0 {
            base64 += String(repeating: "=", count: padding)
        }
        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        let standard = base64EncodedString()
        let noPadding = standard.replacingOccurrences(of: "=", with: "")
        let plusSafe = noPadding.replacingOccurrences(of: "+", with: "-")
        return plusSafe.replacingOccurrences(of: "/", with: "_")
    }
}
