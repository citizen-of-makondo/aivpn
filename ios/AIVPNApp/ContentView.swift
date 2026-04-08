import SwiftUI

struct ContentView: View {
    @StateObject private var viewModel = VPNConnectionViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection Key") {
                    TextEditor(text: $viewModel.keyInput)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 110)

                    Button("Save Key") {
                        _ = viewModel.saveKey()
                    }
                }

                Section("Connection") {
                    LabeledContent("Status", value: viewModel.statusText)

                    Button("Connect") {
                        viewModel.connect()
                    }
                    .disabled(!viewModel.canConnect)

                    Button("Disconnect", role: .destructive) {
                        viewModel.disconnect()
                    }
                    .disabled(!viewModel.canDisconnect)
                }

                if let parsed = viewModel.parsedKey {
                    Section("Parsed Key") {
                        LabeledContent("Server", value: parsed.serverAddress)
                        LabeledContent("Port", value: "\(parsed.port)")
                        LabeledContent("Client ID", value: parsed.clientID)
                    }
                }

                if let message = viewModel.validationMessage {
                    Section("Validation") {
                        Text(message)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("AIVPN")
        }
    }
}

#Preview {
    ContentView()
}
