#!/bin/bash
set -euo pipefail

rm -rf build/
mkdir -p build

echo "Build Started!"
echo

set +eo pipefail
xcodebuild \
  -project lara.xcodeproj \
  -scheme lara \
  -configuration Debug \
  -sdk iphoneos \
  -arch arm64e \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGN_ENTITLEMENTS="Config/lara.entitlements" \
  archive \
  -archivePath "$PWD/build/lara.xcarchive" > /tmp/xcodebuild_full.log 2>&1
BUILD_EXIT=$?
set -eo pipefail

if [ $BUILD_EXIT -ne 0 ]; then
  echo ""
  echo "=== BUILD FAILED (exit code $BUILD_EXIT) ==="
  echo ""
  echo "=== ERRORS ==="
  grep -i "error:" /tmp/xcodebuild_full.log | grep -v "error:" | head -50 || true
  grep " error:" /tmp/xcodebuild_full.log | head -50 || true
  echo ""
  echo "=== LAST 50 LINES ==="
  tail -50 /tmp/xcodebuild_full.log
  exit $BUILD_EXIT
fi

cat /tmp/xcodebuild_full.log | xcpretty || true

APP_PATH="$PWD/build/lara.xcarchive/Products/Applications/lara.app"
if [ ! -d "$APP_PATH" ]; then
  echo "Missing app at $APP_PATH"
  exit 1
fi
rm -rf "$PWD/build/Payload"
mkdir -p "$PWD/build/Payload"
cp -R "$APP_PATH" "$PWD/build/Payload/"

plutil -replace UIFileSharingEnabled -bool YES "$PWD/build/Payload/lara.app/Info.plist"

if ! command -v ldid >/dev/null 2>&1; then
  echo "ERROR: ldid not installed. Install with: brew install ldid" >&2
  exit 1
fi
ldid -SConfig/lara.entitlements "$PWD/build/Payload/lara.app/lara"
(cd "$PWD/build" && /usr/bin/zip -qry dsploit.ipa Payload)

echo
echo "build successful!"
echo "ipa at: build/dsploit.ipa"
exit 0
