#!/usr/bin/env bash
# Builds a Release app, signs it ad hoc (no Developer ID yet) and packs it into
# .build/VaultSyncryptionClient-<version>.dmg with an /Applications link and dmg/Read Me.txt (the
# Terminal commands to clear the quarantine flag and re-sign). Prints the DMG path.
set -euo pipefail
cd "$(dirname "$0")"

version=$(sed -n 's/^ *MARKETING_VERSION: *"\(.*\)"/\1/p' project.yml)
xcodegen --quiet
xcodebuild -project VaultSyncryptionClient.xcodeproj -scheme VaultSyncryptionClient \
  -destination 'generic/platform=macOS' -configuration Release \
  -derivedDataPath .build/xcode-release build >/dev/null

app=.build/xcode-release/Build/Products/Release/VaultSyncryptionClient.app
# Inside out and keeping each bundle's entitlements: --deep would drop the Finder extension's
# sandbox, and Finder loads only sandboxed extensions.
for bundle in "$app"/Contents/PlugIns/*.appex "$app"; do
  codesign --force --options runtime --preserve-metadata=entitlements,identifier --sign - "$bundle" >&2
done
codesign --verify --strict "$app" >&2

stage=$(mktemp -d)
cp -R "$app" "$stage/"
ln -s /Applications "$stage/Applications"
cp "dmg/Read Me.txt" "$stage/"
dmg=.build/VaultSyncryptionClient-${version}.dmg
rm -f "$dmg"
hdiutil create -quiet -volname "Vault Syncryption Client ${version}" -srcfolder "$stage" \
  -format UDZO "$dmg"
rm -rf "$stage"
echo "$dmg"
