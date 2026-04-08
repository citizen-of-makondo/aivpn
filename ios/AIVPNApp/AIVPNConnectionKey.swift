import Foundation

struct AIVPNConnectionKey: Equatable {
    static let schemePrefix = "aivpn://"

    let serverAddress: String
    let sharedKey: String
    let port: Int
    let clientID: String

    init(serverAddress: String, sharedKey: String, port: Int, clientID: String) {
        self.serverAddress = serverAddress
        self.sharedKey = sharedKey
        self.port = port
        self.clientID = clientID
    }

    var rawValue: String {
        let payload = Payload(s: serverAddress, k: sharedKey, p: port, i: clientID)
        let data = try? JSONEncoder().encode(payload)
        let encoded = data?.base64URLEncodedString() ?? ""
        return "\(Self.schemePrefix)\(encoded)"
    }

    static func parse(_ raw: String) throws -> AIVPNConnectionKey {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(Self.schemePrefix) else {
            throw AIVPNKeyParseError.invalidPrefix
        }

        let payloadPart = String(trimmed.dropFirst(Self.schemePrefix.count))
        guard !payloadPart.isEmpty else {
            throw AIVPNKeyParseError.emptyPayload
        }

        guard let data = Data(base64URLEncoded: payloadPart) else {
            throw AIVPNKeyParseError.invalidBase64
        }

        let payload: Payload
        do {
            payload = try JSONDecoder().decode(Payload.self, from: data)
        } catch {
            throw AIVPNKeyParseError.invalidJSON
        }

        let serverAddress = payload.s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !serverAddress.isEmpty else {
            throw AIVPNKeyParseError.missingServer
        }

        let sharedKey = payload.k.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sharedKey.isEmpty else {
            throw AIVPNKeyParseError.missingSharedKey
        }

        guard (1...65_535).contains(payload.p) else {
            throw AIVPNKeyParseError.invalidPort
        }

        let clientID = payload.i.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clientID.isEmpty else {
            throw AIVPNKeyParseError.missingClientID
        }

        return AIVPNConnectionKey(
            serverAddress: serverAddress,
            sharedKey: sharedKey,
            port: payload.p,
            clientID: clientID
        )
    }
}

enum AIVPNKeyParseError: Error, LocalizedError, Equatable {
    case invalidPrefix
    case emptyPayload
    case invalidBase64
    case invalidJSON
    case missingServer
    case missingSharedKey
    case invalidPort
    case missingClientID

    var errorDescription: String? {
        switch self {
        case .invalidPrefix:
            return "Key must start with aivpn://"
        case .emptyPayload:
            return "Key payload is empty"
        case .invalidBase64:
            return "Key payload is not valid Base64URL"
        case .invalidJSON:
            return "Key payload is not valid JSON"
        case .missingServer:
            return "Server address (s) is required"
        case .missingSharedKey:
            return "Shared key (k) is required"
        case .invalidPort:
            return "Port (p) must be in range 1...65535"
        case .missingClientID:
            return "Client id (i) is required"
        }
    }
}

private struct Payload: Codable, Equatable {
    let s: String
    let k: String
    let p: Int
    let i: String
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
