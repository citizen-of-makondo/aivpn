# iOS v1 Status (Token-Safe Delivery)

Last Updated: 2026-04-18 (Phase 4 closed; Phase 5/6 implementation merged, device gate pending)
Branch: `our-prod`
Primary Repo: `origin` (`citizen-of-makondo/aivpn`)

## Decisions Locked

- Release track: Internal TestFlight
- iOS deployment target: iOS 16+
- Routing mode: full tunnel only
- Scope v1: minimum (key import, connect/disconnect, status, basic logs/errors)
- Rust depth: packet core only (Swift handles NE lifecycle and network I/O)
- Key format: unchanged `aivpn://BASE64URL({"s","k","p","i"})`

## Phase Checklist

- [x] Phase 0: Process scaffold (`ios/` folder + this status file)
- [x] Phase 1: Xcode skeleton (App + PacketTunnel extension)
- [x] Phase 2: v1 UI (key input, validation, storage, state)
- [x] Phase 3: Rust iOS core foundation (C ABI + header + XCFramework build)
- [x] Phase 4: Swift <-> Rust bridge (Rust key parsing wired into app + QR import + updated UI)
- [ ] Phase 5: Tunnel lifecycle (implemented in code; needs physical-device gate)
- [ ] Phase 6: Data plane v1 (implemented in code; needs physical-device E2E traffic gate)
- [ ] Phase 7: Resiliency (reconnect/reassert/network switch)
- [ ] Phase 8: Internal TestFlight prep (signing/archive/checklist)

## Per-Phase Gate Rule

Each phase is complete only when all are done:

1. Build/test gate passes.
2. `ios/STATUS.md` updated.
3. Commit created with phase message.
4. Pushed to `origin/our-prod`.

## Latest Gate Results (Current Host)

- Phase 1 build gate passed:
  `xcodebuild -project ios/AIVPN.xcodeproj -scheme AIVPN -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build`

- Phase 2 test gate passed:
  `xcodebuild -project ios/AIVPN.xcodeproj -scheme AIVPN -configuration Debug -destination 'id=BD9B3CE5-780D-4205-9C12-538F80FDF290' CODE_SIGNING_ALLOWED=NO test`

- Phase 3 build gate passed:
  `./ios/rust-core/scripts/build_xcframework.sh`

- Phase 4 regression gate passed (simulator):
  `xcodebuild -project ios/AIVPN.xcodeproj -scheme AIVPN -configuration Debug -destination 'id=BD9B3CE5-780D-4205-9C12-538F80FDF290' CODE_SIGNING_ALLOWED=NO test`

- Local limitation:
  Rust `cargo` commands are unavailable on this host (`cargo: command not found`), so Rust unit/integration gates must be run on a host with Rust toolchain or in CI.

## Device Gates Pending

- Phase 5 gate:
  validate `NETunnelProviderManager` + `PacketTunnelProvider` start/stop on physical iOS device.
- Phase 6 gate:
  validate real traffic flow (`readPackets/encrypt/send` and `recv/decrypt/write`) against running `aivpn-server` and network switch recovery.

## Resume Command

From repo root:

```bash
git checkout our-prod
git pull --ff-only origin our-prod
```

Then continue from the first unchecked phase above.
