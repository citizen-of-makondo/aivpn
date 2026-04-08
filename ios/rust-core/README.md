# AIVPN iOS Rust Core (Phase 3)

This folder contains the iOS Rust foundation crate and fixed C ABI contract for iOS integration.

## Layout

- `aivpn-ios-core/` — Rust crate (`staticlib` + `cdylib`)
- `include/aivpn_ios_core.h` — public C header used by Swift bridge
- `scripts/build_xcframework.sh` — builds `AIVPNIOSCore.xcframework`
- `dist/` — build output

## Phase 3 Scope

- Implemented:
  - `aivpn_parse_key`
  - `aivpn_session_create`
  - `aivpn_session_free`
  - memory free helpers (`aivpn_error_free`, `aivpn_parsed_key_free`, `aivpn_bytes_free`)
- Placeholder stubs (return `AIVPN_ERR_NOT_IMPLEMENTED`):
  - `aivpn_session_build_init`
  - `aivpn_session_encrypt_packet`
  - `aivpn_session_decrypt_packet`
  - `aivpn_session_build_keepalive`

## Build XCFramework

From repository root:

```bash
./ios/rust-core/scripts/build_xcframework.sh
```

Expected output:

`ios/rust-core/dist/AIVPNIOSCore.xcframework`
