import SwiftUI

struct ContentView: View {
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.shield")
                .font(.system(size: 44))
                .foregroundStyle(.blue)
            Text("AIVPN iOS")
                .font(.title2)
                .fontWeight(.semibold)
            Text("Phase 1 skeleton is ready")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(24)
    }
}

#Preview {
    ContentView()
}
