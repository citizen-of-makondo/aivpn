# iOS v1 Roadmap (Post Admin v1)

## Goal

Deliver iOS client after Admin v1 release with protocol compatibility preserved.

## Architecture

- UI: SwiftUI
- Tunnel runtime: `NEPacketTunnelProvider` (Network Extension)
- Protocol core: Rust (`aivpn-common` + client wire path) exposed via FFI
- Connection format: keep current `aivpn://` unchanged

## Milestones

1. FFI bridge
- Build Rust static library for iOS targets
- Expose minimal C ABI for:
  - key parsing
  - packet build/decode
  - session key derivation

2. iOS app skeleton
- App target (SwiftUI)
- Packet Tunnel extension target
- Key import screen + secure storage

3. Tunnel flow
- Start/stop tunnel from UI
- UDP socket loop inside extension
- Reconnect behavior on network changes

4. Validation
- Crypto vector tests vs Rust reference
- Lifecycle tests (background/foreground)
- End-to-end against production `aivpn-server`

5. Release
- TestFlight first
- App Store hardening and submission after TestFlight validation

## Non-goals for iOS v1

- Multi-account admin flows
- Billing
- Protocol format changes
