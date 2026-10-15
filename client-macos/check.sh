#!/usr/bin/env bash
# Tests and builds the macOS client: swift test for the libraries, then the app with
# XcodeGen and xcodebuild. Run from anywhere; used locally and by the beta repo's CI.
set -euo pipefail
cd "$(dirname "$0")"

if command -v uv >/dev/null; then
  echo "==> api-models.py --check"
  uv run --project ../backend --quiet python api-models.py --check
fi

echo "==> swift test"
swift test

echo "==> xcodegen"
xcodegen --quiet

echo "==> xcodebuild"
log=$(mktemp)
if ! xcodebuild -project VaultSyncryption.xcodeproj -scheme VaultSyncryption \
  -destination 'platform=macOS' -configuration Debug -derivedDataPath .build/xcode build >"$log" 2>&1; then
  grep -E "error:" "$log" || tail -30 "$log"
  exit 1
fi
rm -f "$log"
