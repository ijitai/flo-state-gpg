#!/bin/bash
# Runs the core crypto/document tests and the standalone bridge/GnuPG interop
# tests. XCTest is unavailable with Command Line Tools only, so GPGTestRunner is
# a normal executable target.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p .tmp/swiftpm-cache .tmp/swiftpm-config .tmp/clang-module-cache .tmp/tmp
export TMPDIR="$ROOT/.tmp/tmp"
export CLANG_MODULE_CACHE_PATH="$ROOT/.tmp/clang-module-cache"
FLAGS=(--disable-sandbox --cache-path "$ROOT/.tmp/swiftpm-cache" --config-path "$ROOT/.tmp/swiftpm-config")

echo "==> Swift core tests"
swift run "${FLAGS[@]}" GPGTestRunner

echo "==> App-level offscreen flow (real ShellModel/SaveEngine/window)"
BIN="$(swift build "${FLAGS[@]}" --show-bin-path)"
rm -rf "$ROOT/.tmp/app-selftest-ws" "$ROOT/.tmp/app-selftest-data"
printf '%s\n' 'app-selftest-密码-2026' | "$BIN/FloStateNative" \
  --gpg-selftest "$ROOT/.tmp/app-selftest-ws" --data-dir "$ROOT/.tmp/app-selftest-data"

echo "==> C ABI + GnuPG interop"
bash "$ROOT/scripts/test-bridge.sh"
