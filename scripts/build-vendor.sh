#!/bin/bash
# Build the pinned native crypto dependencies and the XCFramework that SwiftPM
# links. No Homebrew runtime dependency: Botan and libencryptmsg are static.
#
# Versions:
#   Botan 3.13.0 (tarball SHA-256 9fbff1cd4fe7caff9bc146304dabf551e05a8beefdf03062b63d02cbb61f2e22)
#   libencryptmsg 1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0 (vendored)
#
# Usage: scripts/build-vendor.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BOTAN_SRC="$ROOT/vendor/src/botan"
LEM_SRC="$ROOT/vendor/src/libencryptmsg"
JOBS="${JOBS:-8}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
BOTAN_VERSION="3.13.0"
BOTAN_SHA256="9fbff1cd4fe7caff9bc146304dabf551e05a8beefdf03062b63d02cbb61f2e22"

mkdir -p "$ROOT/vendor/lib" "$ROOT/vendor/include" "$ROOT/.tmp"

if [[ ! -d "$BOTAN_SRC" ]]; then
  echo "==> fetching Botan $BOTAN_VERSION"
  TMP="$ROOT/.tmp/botan-$BOTAN_VERSION.tar.gz"
  curl -sSL --fail --retry 3 -o "$TMP" \
    "https://github.com/randombit/botan/archive/refs/tags/$BOTAN_VERSION.tar.gz"
  ACTUAL="$(shasum -a 256 "$TMP" | awk '{print $1}')"
  [[ "$ACTUAL" == "$BOTAN_SHA256" ]] || { echo "Botan checksum mismatch: $ACTUAL" >&2; exit 1; }
  tar xzf "$TMP" -C "$ROOT/vendor/src"
  mv "$ROOT/vendor/src/botan-$BOTAN_VERSION" "$BOTAN_SRC"
  rm -f "$TMP"
fi

echo "==> building Botan $BOTAN_VERSION (static, minimal modules)"
cd "$BOTAN_SRC"
if [[ ! -f libbotan-3.a ]]; then
  python3 configure.py \
    --minimized-build \
    --enable-modules=system_rng,auto_rng,sha1,sha2_32,sha2_64,aes,des,cast128,camellia,twofish,cfb,pgp_s2k,zlib,bzip2,mem_pool,base64,crc24 \
    --build-targets=static --without-documentation --disable-shared-library \
    --cc-bin=/usr/bin/clang++ --cxxflags=-mmacosx-version-min=14.0 \
    --ldflags=-mmacosx-version-min=14.0 >/tmp/flo-botan-configure.log
  make -j"$JOBS"
fi
rm -rf "$ROOT/vendor/include/botan"
cp -RL "$BOTAN_SRC/build/include/public/botan" "$ROOT/vendor/include/"

echo "==> building libencryptmsg 1cfa8db (static)"
cd "$LEM_SRC"
if git rev-parse --git-dir >/dev/null 2>&1; then
  ACTUAL="$(git rev-parse HEAD)"
  [[ "$ACTUAL" == "1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0" ]] || {
    echo "libencryptmsg is at $ACTUAL, expected 1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0" >&2; exit 1; }
fi
make distclean >/dev/null 2>&1 || true
python3 configure.py \
  --botan-include-dir="$BOTAN_SRC/build/include/public" \
  --botan-lib-dir="$BOTAN_SRC" \
  --static-linking \
  --pkg-config-bin="$ROOT/scripts/pkg-config-shim" \
  --cxxflags="-DNDEBUG -mmacosx-version-min=14.0" >/tmp/flo-lem-configure.log
make -j"$JOBS"

rm -rf "$ROOT/vendor/include/encryptmsg"
mkdir -p "$ROOT/vendor/include/encryptmsg"
cp "$LEM_SRC"/src/lib/*.h "$ROOT/vendor/include/encryptmsg/"
cp "$BOTAN_SRC/libbotan-3.a" "$ROOT/vendor/lib/libbotan-3.a"
cp "$LEM_SRC/build/libencryptmsg.a" "$ROOT/vendor/lib/libencryptmsg.a"

echo "==> linking merged vendor archive and XCFramework"
/usr/bin/libtool -static -o "$ROOT/vendor/lib/libFloEncryptMsgVendor.a" \
  "$ROOT/vendor/lib/libencryptmsg.a" "$ROOT/vendor/lib/libbotan-3.a"
XCF="$ROOT/vendor/FloEncryptMsgVendor.xcframework"
rm -rf "$XCF"
mkdir -p "$XCF/macos-arm64"
cp "$ROOT/vendor/lib/libFloEncryptMsgVendor.a" "$XCF/macos-arm64/"
cat > "$XCF/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AvailableLibraries</key>
  <array>
    <dict>
      <key>LibraryIdentifier</key>
      <string>macos-arm64</string>
      <key>LibraryPath</key>
      <string>libFloEncryptMsgVendor.a</string>
      <key>SupportedArchitectures</key>
      <array><string>arm64</string></array>
      <key>SupportedPlatform</key>
      <string>macos</string>
    </dict>
  </array>
  <key>CFBundlePackageType</key>
  <string>XFWK</string>
  <key>XCFrameworkFormatVersion</key>
  <string>1.0</string>
</dict>
</plist>
PLIST
plutil -lint "$XCF/Info.plist" >/dev/null
echo "built: $ROOT/vendor/lib/libFloEncryptMsgVendor.a"
