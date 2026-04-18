import AVFoundation
import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var viewModel = VPNConnectionViewModel()
    @State private var isShowingQRScanner = false

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.05, green: 0.08, blue: 0.16), Color(red: 0.04, green: 0.2, blue: 0.28)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 16) {
                    headerCard
                    keyCard
                    actionsCard
                    detailsCard
                    logsCard
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 20)
            }
        }
        .sheet(isPresented: $isShowingQRScanner) {
            QRScannerContainerView { key in
                viewModel.importKeyFromQRCode(key)
                isShowingQRScanner = false
            }
        }
    }

    private var headerCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("AIVPN")
                .font(.system(size: 32, weight: .bold, design: .rounded))
                .foregroundStyle(.white)

            Text("iOS v1 — full tunnel")
                .font(.system(size: 14, weight: .medium, design: .rounded))
                .foregroundStyle(.white.opacity(0.75))

            HStack(spacing: 8) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                Text(viewModel.statusText)
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(.white.opacity(0.12), in: Capsule())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var keyCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Connection Key")
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)

            TextEditor(text: $viewModel.keyInput)
                .font(.system(size: 13, weight: .regular, design: .monospaced))
                .frame(minHeight: 130)
                .padding(8)
                .background(Color.black.opacity(0.25), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .foregroundStyle(.white)

            HStack(spacing: 8) {
                Button("Paste") {
                    if let text = UIPasteboard.general.string {
                        viewModel.keyInput = text
                        _ = viewModel.saveKey()
                    }
                }
                .buttonStyle(SecondaryActionButtonStyle())

                Button("Scan QR") {
                    isShowingQRScanner = true
                }
                .buttonStyle(SecondaryActionButtonStyle())

                Button("Save") {
                    _ = viewModel.saveKey()
                }
                .buttonStyle(SecondaryActionButtonStyle())
            }

            if let message = viewModel.validationMessage {
                Text(message)
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.77, blue: 0.77))
            }

            if let error = viewModel.lastError {
                Text(error)
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(Color(red: 1.0, green: 0.6, blue: 0.6))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var actionsCard: some View {
        VStack(spacing: 12) {
            Button {
                viewModel.connect()
            } label: {
                Text("Connect")
                    .font(.system(size: 17, weight: .semibold, design: .rounded))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(PrimaryActionButtonStyle(color: Color(red: 0.2, green: 0.82, blue: 0.53)))
            .disabled(!viewModel.canConnect)

            Button {
                viewModel.disconnect()
            } label: {
                Text("Disconnect")
                    .font(.system(size: 17, weight: .semibold, design: .rounded))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(PrimaryActionButtonStyle(color: Color(red: 0.86, green: 0.25, blue: 0.32)))
            .disabled(!viewModel.canDisconnect)
        }
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var detailsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Session")
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)

            if let parsed = viewModel.parsedKey {
                detailRow(label: "Endpoint", value: parsed.serverEndpoint)
                detailRow(label: "Host", value: parsed.host)
                detailRow(label: "Port", value: "\(parsed.port)")
                detailRow(label: "Client IP", value: parsed.clientIPAddress)
                detailRow(label: "PSK", value: parsed.preSharedKeyBase64 == nil ? "none" : "present")
            } else {
                Text("No valid key loaded")
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.7))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func detailRow(label: String, value: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(label)
                .font(.system(size: 12, weight: .semibold, design: .rounded))
                .foregroundStyle(.white.opacity(0.7))
                .frame(width: 74, alignment: .leading)

            Text(value)
                .font(.system(size: 12, weight: .regular, design: .monospaced))
                .foregroundStyle(.white)
                .textSelection(.enabled)

            Spacer(minLength: 0)
        }
    }

    private var logsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Event Log")
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)

            if viewModel.events.isEmpty {
                Text("No events yet")
                    .font(.system(size: 12, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.7))
            } else {
                ForEach(viewModel.events.prefix(12), id: \.self) { event in
                    Text(event)
                        .font(.system(size: 11, weight: .regular, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.9))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var statusColor: Color {
        switch viewModel.status {
        case .connected:
            return Color(red: 0.28, green: 0.9, blue: 0.58)
        case .connecting:
            return Color(red: 1.0, green: 0.76, blue: 0.24)
        case .disconnecting:
            return Color(red: 0.95, green: 0.62, blue: 0.24)
        case .disconnected:
            return Color(red: 1.0, green: 0.42, blue: 0.42)
        }
    }
}

private struct PrimaryActionButtonStyle: ButtonStyle {
    let color: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.vertical, 12)
            .foregroundStyle(.white)
            .background(color.opacity(configuration.isPressed ? 0.7 : 1.0), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct SecondaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 14, weight: .semibold, design: .rounded))
            .foregroundStyle(.white)
            .padding(.vertical, 8)
            .padding(.horizontal, 12)
            .background(Color.white.opacity(configuration.isPressed ? 0.15 : 0.2), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct QRScannerContainerView: View {
    let onKeyScanned: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var scannerError: String?

    var body: some View {
        NavigationStack {
            ZStack {
                QRScannerView(
                    onCodeScanned: { code in
                        onKeyScanned(code)
                    },
                    onFailure: { error in
                        scannerError = error.localizedDescription
                    }
                )
                .ignoresSafeArea()

                if let scannerError {
                    VStack {
                        Spacer()
                        Text(scannerError)
                            .font(.system(size: 13, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                            .padding(12)
                            .background(Color.red.opacity(0.8), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                            .padding(16)
                    }
                }
            }
            .navigationTitle("Scan AIVPN QR")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Close") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct QRScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void
    let onFailure: (Error) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let viewController = QRScannerViewController()
        viewController.onCodeScanned = onCodeScanned
        viewController.onFailure = onFailure
        return viewController
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {
        uiViewController.onCodeScanned = onCodeScanned
        uiViewController.onFailure = onFailure
    }
}

final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCodeScanned: ((String) -> Void)?
    var onFailure: ((Error) -> Void)?

    private let captureSession = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var didEmitCode = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureCamera()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        captureSession.stopRunning()
    }

    private func configureCamera() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            setupSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted {
                        self?.setupSession()
                    } else {
                        self?.onFailure?(QRScannerError.cameraDenied)
                    }
                }
            }
        case .denied, .restricted:
            onFailure?(QRScannerError.cameraDenied)
        @unknown default:
            onFailure?(QRScannerError.cameraUnavailable)
        }
    }

    private func setupSession() {
        guard let videoDevice = AVCaptureDevice.default(for: .video) else {
            onFailure?(QRScannerError.cameraUnavailable)
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: videoDevice)
            guard captureSession.canAddInput(input) else {
                onFailure?(QRScannerError.cameraUnavailable)
                return
            }
            captureSession.addInput(input)

            let output = AVCaptureMetadataOutput()
            guard captureSession.canAddOutput(output) else {
                onFailure?(QRScannerError.cameraUnavailable)
                return
            }
            captureSession.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            output.metadataObjectTypes = [.qr]

            let preview = AVCaptureVideoPreviewLayer(session: captureSession)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.layer.bounds
            view.layer.addSublayer(preview)
            self.previewLayer = preview

            captureSession.startRunning()
        } catch {
            onFailure?(error)
        }
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !didEmitCode else {
            return
        }

        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let code = object.stringValue else {
            return
        }

        didEmitCode = true
        captureSession.stopRunning()
        onCodeScanned?(code)
    }
}

enum QRScannerError: LocalizedError {
    case cameraDenied
    case cameraUnavailable

    var errorDescription: String? {
        switch self {
        case .cameraDenied:
            return "Camera permission is required to scan QR."
        case .cameraUnavailable:
            return "Camera is unavailable on this device."
        }
    }
}

#Preview {
    ContentView()
}
