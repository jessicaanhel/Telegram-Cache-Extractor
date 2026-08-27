#!/bin/bash
# TelegramCacheExtractor-macos — macOS-only build. Does not touch installer.iss or the Windows flow.
# Run from the repo root:
#   chmod +x macos/build.sh && ./macos/build.sh
set -euo pipefail

APP="TelegramCacheExtractor-macos"
VER="1.0.0"
DIST="dist"

command -v ffmpeg >/dev/null || { echo "ffmpeg not found — brew install ffmpeg"; exit 1; }
FFMPEG="$(command -v ffmpeg)"

python3 -m pip install --upgrade pyinstaller pywebview pycryptodome >/dev/null

rm -rf build "$DIST" "$APP.spec"

pyinstaller \
  --name "$APP" \
  --windowed \
  --noconfirm \
  --icon icon.icns \
  --paths . \
  --add-data "macos/ui:ui" \
  --add-binary "$FFMPEG:." \
  --osx-bundle-identifier "com.flexair.telegramcacheextractor-macos" \
  macos/main.py

# --- ad-hoc sign; swap for your Developer ID before distributing ---
# NOTE: no --options runtime here — hardened runtime enables Library
# Validation, which requires every loaded binary to share the main
# executable's Team ID. Ad-hoc signatures have no Team ID, so the embedded
# Python.framework would fail to load ("different Team IDs") at launch.
# Hardened runtime is only safe once a real Developer ID is used below.
codesign --force --deep --sign - "$DIST/$APP.app"
# codesign --force --deep --options runtime --timestamp \
#   --sign "Developer ID Application: YOUR NAME (TEAMID)" "$DIST/$APP.app"

# --- dmg ---
STAGE="$DIST/dmg"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -R "$DIST/$APP.app" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP" -srcfolder "$STAGE" -ov -format UDZO "$DIST/$APP-$VER.dmg"
rm -rf "$STAGE"

echo "→ $DIST/$APP-$VER.dmg"
echo "Notarize before sharing:"
echo "  xcrun notarytool submit \"$DIST/$APP-$VER.dmg\" --apple-id you@example.com --team-id TEAMID --password APP-SPECIFIC --wait"
echo "  xcrun stapler staple \"$DIST/$APP-$VER.dmg\""
