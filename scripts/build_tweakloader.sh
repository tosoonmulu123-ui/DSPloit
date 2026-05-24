#!/bin/bash
# Build TweakLoader.dylib — the dylib that gets injected into processes
# This is compiled separately from the main app and bundled as a resource.
#
# Usage: ./scripts/build_tweakloader.sh
# Output: build/TweakLoader.dylib (to be included in app bundle)

set -euo pipefail

SRCDIR="lara/kexploit"
OUTDIR="build"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --sdk iphoneos -f clang)

mkdir -p "$OUTDIR"

echo "Building TweakLoader.dylib..."

$CC \
  -arch arm64e \
  -isysroot "$SDK" \
  -dynamiclib \
  -install_name /var/jb/usr/lib/TweakLoader.dylib \
  -framework Foundation \
  -lobjc \
  -O2 \
  -o "$OUTDIR/TweakLoader.dylib" \
  "$SRCDIR/TweakLoaderDylib.m"

if [ -f "$OUTDIR/TweakLoader.dylib" ]; then
  echo "✅ TweakLoader.dylib built successfully"
  ls -la "$OUTDIR/TweakLoader.dylib"
  
  # Sign with ldid if available
  if command -v ldid >/dev/null 2>&1; then
    ldid -S "$OUTDIR/TweakLoader.dylib"
    echo "✅ Signed with ldid"
  fi
else
  echo "❌ Build failed"
  exit 1
fi
