import Combine
import Foundation

enum VPNConnectionStatus: Equatable {
    case disconnected
    case connecting
    case connected
}

protocol KeyValueStore {
    func string(forKey key: String) -> String?
    func set(_ value: String?, forKey key: String)
}

final class UserDefaultsKeyValueStore: KeyValueStore {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    func string(forKey key: String) -> String? {
        defaults.string(forKey: key)
    }

    func set(_ value: String?, forKey key: String) {
        if let value {
            defaults.set(value, forKey: key)
        } else {
            defaults.removeObject(forKey: key)
        }
    }
}

@MainActor
final class VPNConnectionViewModel: ObservableObject {
    static let storedConnectionKeyKey = "aivpn.connectionKey"

    @Published var keyInput: String = ""
    @Published private(set) var status: VPNConnectionStatus = .disconnected
    @Published private(set) var parsedKey: AIVPNConnectionKey?
    @Published private(set) var validationMessage: String?

    private let store: KeyValueStore

    init(store: KeyValueStore = UserDefaultsKeyValueStore()) {
        self.store = store
        loadStoredKey()
    }

    var statusText: String {
        switch status {
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting"
        case .connected:
            return "Connected"
        }
    }

    var canConnect: Bool {
        status != .connected
    }

    var canDisconnect: Bool {
        status != .disconnected
    }

    @discardableResult
    func saveKey() -> Bool {
        validateAndPersist(raw: keyInput, persist: true)
    }

    func connect() {
        guard saveKey() else {
            status = .disconnected
            return
        }

        status = .connecting
        status = .connected
    }

    func disconnect() {
        status = .disconnected
    }

    private func loadStoredKey() {
        guard let stored = store.string(forKey: Self.storedConnectionKeyKey), !stored.isEmpty else {
            return
        }

        keyInput = stored
        _ = validateAndPersist(raw: stored, persist: false)
    }

    @discardableResult
    private func validateAndPersist(raw: String, persist: Bool) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            parsedKey = nil
            validationMessage = "Connection key is required"
            return false
        }

        do {
            let parsed = try AIVPNConnectionKey.parse(trimmed)
            parsedKey = parsed
            validationMessage = nil
            if persist {
                let normalized = parsed.rawValue
                keyInput = normalized
                store.set(normalized, forKey: Self.storedConnectionKeyKey)
            }
            return true
        } catch let parseError as AIVPNKeyParseError {
            parsedKey = nil
            validationMessage = parseError.localizedDescription
            return false
        } catch {
            parsedKey = nil
            validationMessage = "Unknown key parse error"
            return false
        }
    }
}
