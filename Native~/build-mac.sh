#!/usr/bin/env bash
# Compila el backend de Apple para macOS: Plugins/macOS/libDotrinoCrypto.dylib, universal
# (Intel y Apple Silicon), desde la MISMA fuente que Unity compila en iOS. Corre en un Mac con Xcode.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=Plugins/iOS/DotrinoCrypto.swift
OUT=Plugins/macOS/libDotrinoCrypto.dylib
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for arch in x86_64 arm64; do
  swiftc -O -emit-library -module-name DotrinoCrypto -target "$arch-apple-macos11" "$SRC" -o "$TMP/$arch.dylib"
done
mkdir -p "$(dirname "$OUT")"
lipo -create "$TMP/x86_64.dylib" "$TMP/arm64.dylib" -output "$OUT"
install_name_tool -id @rpath/libDotrinoCrypto.dylib "$OUT"
lipo -info "$OUT"
shasum -a 256 "$OUT"
