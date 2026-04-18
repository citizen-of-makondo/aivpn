import Combine
import Foundation
import NetworkExtension

enum VPNConnectionStatus: Equatable {
    case disconnected
    case connecting
    case connected
    case disconnecting
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

protocol VPNController {
    func start(connectionKey: String) async throws
    func stop() async
    func status() async -> NEVPNStatus
}

actor NETunnelVPNController: VPNController {
    private static let tunnelBundleIdentifier = "com.aivpn.ios.tunnel"
    private static let loadRetryBackoffSeconds: TimeInterval = 15

    private var manager: NETunnelProviderManager?
    private var nextStatusReloadAllowedAt: Date = .distantPast

    func start(connectionKey: String) async throws {
        let parsed = try AIVPNConnectionKey.parse(connectionKey)
        let manager: NETunnelProviderManager
        do {
            manager = try await loadOrCreateManager()
            nextStatusReloadAllowedAt = .distantPast
        } catch {
            throw mapConfigurationError(error)
        }

        let provider = NETunnelProviderProtocol()
        provider.providerBundleIdentifier = Self.tunnelBundleIdentifier
        provider.serverAddress = parsed.serverEndpoint
        provider.providerConfiguration = [
            "connectionKey": connectionKey,
            "serverEndpoint": parsed.serverEndpoint,
            "clientIPAddress": parsed.clientIPAddress,
        ]

        manager.localizedDescription = "AIVPN"
        manager.protocolConfiguration = provider
        manager.isEnabled = true

        try await save(manager)
        try await load(manager)

        let options: [String: NSObject] = [
            "connectionKey": connectionKey as NSString,
        ]

        if manager.connection.status == .connected || manager.connection.status == .connecting {
            return
        }

        try manager.connection.startVPNTunnel(options: options)
    }

    func stop() async {
        guard let manager else {
            return
        }
        manager.connection.stopVPNTunnel()
    }

    func status() async -> NEVPNStatus {
        if manager == nil {
            let now = Date()
            guard now >= nextStatusReloadAllowedAt else {
                return .disconnected
            }

            do {
                _ = try await loadOrCreateManager()
                nextStatusReloadAllowedAt = .distantPast
            } catch {
                nextStatusReloadAllowedAt = now.addingTimeInterval(Self.loadRetryBackoffSeconds)
                return .disconnected
            }
        }
        return manager?.connection.status ?? .disconnected
    }

    private func mapConfigurationError(_ error: Error) -> Error {
        let nsError = error as NSError
        if nsError.domain == "NEConfigurationErrorDomain", nsError.code == 10 {
            return VPNControllerError.permissionDenied
        }
        return error
    }

    private func loadOrCreateManager() async throws -> NETunnelProviderManager {
        if let manager {
            return manager
        }

        let managers = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[NETunnelProviderManager], Error>) in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: managers ?? [])
                }
            }
        }

        if let existing = managers.first {
            self.manager = existing
            return existing
        }

        let created = NETunnelProviderManager()
        self.manager = created
        return created
    }

    private func save(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }

    private func load(_ manager: NETunnelProviderManager) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            manager.loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
    }
}

enum VPNControllerError: LocalizedError {
    case permissionDenied

    var errorDescription: String? {
        switch self {
        case .permissionDenied:
            return "VPN permission denied. Check Network Extension capability and signing profile."
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
    @Published private(set) var lastError: String?
    @Published private(set) var events: [String] = []

    private let store: KeyValueStore
    private let controller: VPNController
    private var statusTask: Task<Void, Never>?

    init(
        store: KeyValueStore = UserDefaultsKeyValueStore(),
        controller: VPNController = NETunnelVPNController()
    ) {
        self.store = store
        self.controller = controller
        loadStoredKey()
        startStatusPolling()
    }

    deinit {
        statusTask?.cancel()
    }

    var statusText: String {
        switch status {
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting"
        case .connected:
            return "Connected"
        case .disconnecting:
            return "Disconnecting"
        }
    }

    var canConnect: Bool {
        status == .disconnected
    }

    var canDisconnect: Bool {
        status == .connected || status == .connecting
    }

    @discardableResult
    func saveKey() -> Bool {
        validateAndPersist(raw: keyInput, persist: true)
    }

    func importKeyFromQRCode(_ key: String) {
        keyInput = key
        _ = saveKey()
        appendEvent("QR key imported")
    }

    func connect() {
        guard saveKey() else {
            status = .disconnected
            return
        }

        lastError = nil
        status = .connecting
        appendEvent("Connect requested")

        let key = keyInput
        Task {
            do {
                try await controller.start(connectionKey: key)
                await refreshStatus()
                appendEvent("Tunnel start requested")
            } catch {
                status = .disconnected
                let message = formatError(error)
                lastError = message
                appendEvent("Connect failed: \(message)")
            }
        }
    }

    func disconnect() {
        status = .disconnecting
        appendEvent("Disconnect requested")

        Task {
            await controller.stop()
            try? await Task.sleep(for: .milliseconds(300))
            await refreshStatus()
            appendEvent("Tunnel stop requested")
        }
    }

    private func loadStoredKey() {
        guard let stored = store.string(forKey: Self.storedConnectionKeyKey), !stored.isEmpty else {
            return
        }

        keyInput = stored
        _ = validateAndPersist(raw: stored, persist: false)
    }

    private func startStatusPolling() {
        statusTask?.cancel()
        statusTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                await self.refreshStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func appendEvent(_ message: String) {
        let timestamp = ISO8601DateFormatter().string(from: Date())
        events.insert("\(timestamp) \(message)", at: 0)
        if events.count > 100 {
            events.removeLast(events.count - 100)
        }
    }

    private func mapStatus(_ status: NEVPNStatus) -> VPNConnectionStatus {
        switch status {
        case .connected:
            return .connected
        case .connecting, .reasserting:
            return .connecting
        case .disconnecting:
            return .disconnecting
        case .disconnected, .invalid:
            return .disconnected
        @unknown default:
            return .disconnected
        }
    }

    private func refreshStatus() async {
        let systemStatus = await controller.status()
        self.status = mapStatus(systemStatus)
    }

    private func formatError(_ error: Error) -> String {
        if let controllerError = error as? VPNControllerError {
            return controllerError.localizedDescription
        }

        let nsError = error as NSError
        if nsError.domain == "NEConfigurationErrorDomain", nsError.code == 10 {
            return "VPN permission denied. Check Network Extension capability and signing profile."
        }

        return error.localizedDescription
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
                appendEvent("Connection key saved")
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
