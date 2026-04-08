#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$ROOT_DIR/aivpn-ios-core"
INCLUDE_DIR="$ROOT_DIR/include"
DIST_DIR="$ROOT_DIR/dist"

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  rustup target add "$target" >/dev/null
done

cargo build \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --target aarch64-apple-ios \
  --release

cargo build \
  --manifest-path "$CRATE_DIR/Cargo.toml" \
  --target aarch64-apple-ios-sim \
  --release

IOS_LIB="$CRATE_DIR/target/aarch64-apple-ios/release/libaivpn_ios_core.a"
SIM_LIB="$CRATE_DIR/target/aarch64-apple-ios-sim/release/libaivpn_ios_core.a"
OUTPUT_XCFRAMEWORK="$DIST_DIR/AIVPNIOSCore.xcframework"

mkdir -p "$DIST_DIR"
rm -rf "$OUTPUT_XCFRAMEWORK"

xcodebuild -create-xcframework \
  -library "$IOS_LIB" -headers "$INCLUDE_DIR" \
  -library "$SIM_LIB" -headers "$INCLUDE_DIR" \
  -output "$OUTPUT_XCFRAMEWORK"

echo "Built: $OUTPUT_XCFRAMEWORK"
