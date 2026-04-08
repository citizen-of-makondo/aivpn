# iOS v1 Status (Token-Safe Delivery)

Last Updated: 2026-04-08 (Phase 2 closed)
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
- [ ] Phase 3: Rust iOS core foundation (C ABI + header + XCFramework build)
- [ ] Phase 4: Swift <-> Rust bridge (Rust key parsing wired into app)
- [ ] Phase 5: Tunnel lifecycle (start/stop + UDP endpoint + init packet)
- [ ] Phase 6: Data plane v1 (read/write packets via Rust core)
- [ ] Phase 7: Resiliency (reconnect/reassert/network switch)
- [ ] Phase 8: Internal TestFlight prep (signing/archive/checklist)

## Per-Phase Gate Rule

Each phase is complete only when all are done:

1. Build/test gate passes.
2. `ios/STATUS.md` updated.
3. Commit created with phase message.
4. Pushed to `origin/our-prod`.

## Latest Gate Results

- Phase 1 build gate passed:
  `xcodebuild -project ios/AIVPN.xcodeproj -scheme AIVPN -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO build`

- Phase 2 test gate passed:
  `xcodebuild -project ios/AIVPN.xcodeproj -scheme AIVPN -configuration Debug -destination 'id=BD9B3CE5-780D-4205-9C12-538F80FDF290' CODE_SIGNING_ALLOWED=NO test`

## Resume Command

From repo root:

```bash
git checkout our-prod
git pull --ff-only origin our-prod
```

Then continue from the first unchecked phase above.
