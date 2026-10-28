#!/bin/bash
# Release build of this fork: "Flo State GPG.app".
# Keeps SwiftPM caches inside the repo so it also works under a restrictive
# outer sandbox (SwiftPM's own sandbox is disabled for that reason).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p .tmp/swiftpm-cache .tmp/swiftpm-config .tmp/clang-module-cache .tmp/tmp
export TMPDIR="$ROOT/.tmp/tmp"
export CLANG_MODULE_CACHE_PATH="$ROOT/.tmp/clang-module-cache"
export SWIFT_BUILD_FLAGS="--disable-sandbox --cache-path $ROOT/.tmp/swiftpm-cache --config-path $ROOT/.tmp/swiftpm-config"
export APP_NAME="Flo State GPG"
export BUNDLE_ID="app.flostate.gpg"
export JOBS="${JOBS:-8}"
exec "$ROOT/scripts/bundle.sh"
