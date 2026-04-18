import NetworkExtension
import XCTest
@testable import AIVPN

final class AIVPNTests: XCTestCase {
    func testParseValidKeyViaRust() throws {
        let raw = makeRawKey(
            endpoint: "194.154.25.21:443",
            serverPublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            psk: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            clientIP: "10.0.0.2"
        )
        let parsed = try AIVPNConnectionKey.parse(raw)

        XCTAssertEqual(parsed.serverEndpoint, "194.154.25.21:443")
        XCTAssertEqual(parsed.host, "194.154.25.21")
        XCTAssertEqual(parsed.port, 443)
        XCTAssertEqual(parsed.clientIPAddress, "10.0.0.2")
        XCTAssertNotNil(parsed.preSharedKeyBase64)
    }

    func testParseFailsOnInvalidPrefix() {
        XCTAssertThrowsError(try AIVPNConnectionKey.parse("vless://abc")) { error in
            XCTAssertEqual(error as? AIVPNKeyParseError, .invalidPrefix)
        }
    }

    @MainActor
    func testViewModelConnectStoresKeyAndRequestsTunnelStart() async {
        let store = InMemoryKeyValueStore()
        let controller = MockVPNController()
        let viewModel = VPNConnectionViewModel(store: store, controller: controller)
        viewModel.keyInput = makeRawKey(
            endpoint: "example.org:443",
            serverPublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            psk: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            clientIP: "10.0.0.9"
        )

        viewModel.connect()
        try? await Task.sleep(for: .milliseconds(50))

        XCTAssertNotNil(store.string(forKey: VPNConnectionViewModel.storedConnectionKeyKey))
        let startCalls = await controller.getStartCallCount()
        XCTAssertEqual(startCalls, 1)
    }

    @MainActor
    func testViewModelConnectRejectsInvalidKey() async {
        let store = InMemoryKeyValueStore()
        let controller = MockVPNController()
        let viewModel = VPNConnectionViewModel(store: store, controller: controller)
        viewModel.keyInput = "invalid-key"

        viewModel.connect()
        try? await Task.sleep(for: .milliseconds(30))

        XCTAssertEqual(viewModel.status, .disconnected)
        XCTAssertNotNil(viewModel.validationMessage)
        XCTAssertNil(store.string(forKey: VPNConnectionViewModel.storedConnectionKeyKey))
        let startCalls = await controller.getStartCallCount()
        XCTAssertEqual(startCalls, 0)
    }

    @MainActor
    func testViewModelLoadsStoredKeyOnInit() {
        let raw = makeRawKey(
            endpoint: "example.org:443",
            serverPublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            psk: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            clientIP: "10.0.0.20"
        )
        let store = InMemoryKeyValueStore(initial: [VPNConnectionViewModel.storedConnectionKeyKey: raw])

        let viewModel = VPNConnectionViewModel(store: store, controller: MockVPNController())

        XCTAssertEqual(viewModel.keyInput, raw)
        XCTAssertEqual(viewModel.parsedKey?.clientIPAddress, "10.0.0.20")
    }

    private func makeRawKey(endpoint: String, serverPublicKey: String, psk: String, clientIP: String) -> String {
        let payload: [String: String] = [
            "s": endpoint,
            "k": serverPublicKey,
            "p": psk,
            "i": clientIP,
        ]
        let data = try! JSONSerialization.data(withJSONObject: payload, options: [])
        let encoded = data.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        return "aivpn://\(encoded)"
    }
}

private final class InMemoryKeyValueStore: KeyValueStore {
    private var storage: [String: String]

    init(initial: [String: String] = [:]) {
        self.storage = initial
    }

    func string(forKey key: String) -> String? {
        storage[key]
    }

    func set(_ value: String?, forKey key: String) {
        if let value {
            storage[key] = value
        } else {
            storage.removeValue(forKey: key)
        }
    }
}

actor MockVPNController: VPNController {
    private(set) var startCallCount = 0
    private var currentStatus: NEVPNStatus = .disconnected

    func start(connectionKey: String) async throws {
        startCallCount += 1
        currentStatus = .connected
    }

    func stop() async {
        currentStatus = .disconnected
    }

    func status() async -> NEVPNStatus {
        currentStatus
    }

    func getStartCallCount() async -> Int {
        startCallCount
    }
}
