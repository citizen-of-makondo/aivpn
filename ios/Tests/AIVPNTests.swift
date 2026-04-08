import XCTest
@testable import AIVPN

final class AIVPNTests: XCTestCase {
    func testParseValidKey() throws {
        let raw = makeRawKey(server: "194.154.25.21", sharedKey: "secret", port: 443, clientID: "abc123")
        let parsed = try AIVPNConnectionKey.parse(raw)

        XCTAssertEqual(parsed.serverAddress, "194.154.25.21")
        XCTAssertEqual(parsed.sharedKey, "secret")
        XCTAssertEqual(parsed.port, 443)
        XCTAssertEqual(parsed.clientID, "abc123")
    }

    func testParseFailsOnInvalidPrefix() {
        XCTAssertThrowsError(try AIVPNConnectionKey.parse("vless://abc")) { error in
            XCTAssertEqual(error as? AIVPNKeyParseError, .invalidPrefix)
        }
    }

    func testParseFailsOnInvalidPort() {
        let raw = makeRawKey(server: "example.org", sharedKey: "secret", port: 70_000, clientID: "abc")
        XCTAssertThrowsError(try AIVPNConnectionKey.parse(raw)) { error in
            XCTAssertEqual(error as? AIVPNKeyParseError, .invalidPort)
        }
    }

    @MainActor
    func testViewModelConnectStoresKeyAndSetsConnected() {
        let store = InMemoryKeyValueStore()
        let viewModel = VPNConnectionViewModel(store: store)
        viewModel.keyInput = makeRawKey(server: "example.org", sharedKey: "secret", port: 443, clientID: "cli-1")

        viewModel.connect()

        XCTAssertEqual(viewModel.status, .connected)
        XCTAssertNil(viewModel.validationMessage)
        XCTAssertNotNil(store.string(forKey: VPNConnectionViewModel.storedConnectionKeyKey))
    }

    @MainActor
    func testViewModelConnectRejectsInvalidKey() {
        let store = InMemoryKeyValueStore()
        let viewModel = VPNConnectionViewModel(store: store)
        viewModel.keyInput = "invalid-key"

        viewModel.connect()

        XCTAssertEqual(viewModel.status, .disconnected)
        XCTAssertNotNil(viewModel.validationMessage)
        XCTAssertNil(store.string(forKey: VPNConnectionViewModel.storedConnectionKeyKey))
    }

    @MainActor
    func testViewModelLoadsStoredKeyOnInit() {
        let raw = makeRawKey(server: "example.org", sharedKey: "secret", port: 443, clientID: "persisted")
        let store = InMemoryKeyValueStore(initial: [VPNConnectionViewModel.storedConnectionKeyKey: raw])

        let viewModel = VPNConnectionViewModel(store: store)

        XCTAssertEqual(viewModel.keyInput, raw)
        XCTAssertEqual(viewModel.parsedKey?.clientID, "persisted")
    }

    private func makeRawKey(server: String, sharedKey: String, port: Int, clientID: String) -> String {
        AIVPNConnectionKey(serverAddress: server, sharedKey: sharedKey, port: port, clientID: clientID).rawValue
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
