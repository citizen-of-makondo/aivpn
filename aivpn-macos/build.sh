#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
APP_BUNDLE="$BUILD_DIR/Aivpn.app"
CONTENTS="$APP_BUNDLE/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"

echo "🔨 Building AIVPN macOS app (Universal Binary)..."

# Clean
rm -rf "$BUILD_DIR"
mkdir -p "$MACOS" "$RESOURCES" "$BUILD_DIR/arm64" "$BUILD_DIR/x86_64"

# Compile for arm64
echo "📦 Compiling for arm64 (Apple Silicon)..."
swiftc \
    -o "$BUILD_DIR/arm64/Aivpn" \
    -target arm64-apple-macosx13.0 \
    -parse-as-library \
    -framework Cocoa \
    -framework SwiftUI \
    -framework Security \
    -framework Foundation \
    -module-name Aivpn \
    "$SCRIPT_DIR/AivpnApp.swift" \
    "$SCRIPT_DIR/ContentView.swift" \
    "$SCRIPT_DIR/VPNManager.swift" \
    "$SCRIPT_DIR/LocalizationManager.swift" \
    "$SCRIPT_DIR/KeychainHelper.swift"

# Compile for x86_64
echo "📦 Compiling for x86_64 (Intel)..."
swiftc \
    -o "$BUILD_DIR/x86_64/Aivpn" \
    -target x86_64-apple-macosx13.0 \
    -parse-as-library \
    -framework Cocoa \
    -framework SwiftUI \
    -framework Security \
    -framework Foundation \
    -module-name Aivpn \
    "$SCRIPT_DIR/AivpnApp.swift" \
    "$SCRIPT_DIR/ContentView.swift" \
    "$SCRIPT_DIR/VPNManager.swift" \
    "$SCRIPT_DIR/LocalizationManager.swift" \
    "$SCRIPT_DIR/KeychainHelper.swift"

# Create universal binary with lipo
echo "🔗 Creating universal binary..."
lipo -create \
    "$BUILD_DIR/arm64/Aivpn" \
    "$BUILD_DIR/x86_64/Aivpn" \
    -output "$MACOS/Aivpn"

echo "  ✅ $(file "$MACOS/Aivpn" | sed 's/.*: //')"

# Copy aivpn-client binary into Resources
echo "📦 Bundling aivpn-client binary..."
CLIENT_BIN="$PROJECT_DIR/target/release/aivpn-client"
if [ -f "$CLIENT_BIN" ]; then
    cp "$CLIENT_BIN" "$RESOURCES/aivpn-client"
    chmod +x "$RESOURCES/aivpn-client"
    echo "  ✅ aivpn-client bundled ($(file "$RESOURCES/aivpn-client" | sed 's/.*: //'))"
else
    echo "  ⚠️  aivpn-client not found at $CLIENT_BIN"
    echo "  Run 'cargo build --release --bin aivpn-client' first"
fi

# Copy Info.plist
cp "$SCRIPT_DIR/Info.plist" "$CONTENTS/Info.plist"

# Copy entitlements
cp "$SCRIPT_DIR/Aivpn.entitlements" "$CONTENTS/Resources/"

# Create PkgInfo
echo -n "APPL????" > "$CONTENTS/PkgInfo"

# Create minimal Assets.xcassets
mkdir -p "$RESOURCES/Assets.xcassets/AppIcon.appiconset"
cat > "$RESOURCES/Assets.xcassets/AppIcon.appiconset/Contents.json" << 'EOF'
{
  "images" : [
    {
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "16x16"
    },
    {
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "16x16"
    },
    {
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "32x32"
    },
    {
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "32x32"
    },
    {
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "128x128"
    },
    {
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "128x128"
    },
    {
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "256x256"
    },
    {
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "256x256"
    },
    {
      "idiom" : "mac",
      "scale" : "1x",
      "size" : "512x512"
    },
    {
      "idiom" : "mac",
      "scale" : "2x",
      "size" : "512x512"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
EOF

cat > "$RESOURCES/Assets.xcassets/Contents.json" << 'EOF'
{
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
EOF

echo ""
echo "✅ Build complete: $APP_BUNDLE"
echo ""
echo "To run:"
echo "  open $APP_BUNDLE"
echo ""
echo "To create DMG:"
echo "  hdiutil create -volname AIVPN -srcfolder $APP_BUNDLE -ov -format UDZO aivpn-macos.dmg"
