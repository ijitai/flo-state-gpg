#!/bin/bash
# Builds the C ABI bridge standalone, runs its tests, then verifies both
# directions against GnuPG in an isolated GNUPGHOME. Passwords go through a
# pipe / file descriptor, never argv or logs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
WORK="$ROOT/.tmp/bridge-test"
rm -rf "$WORK"
mkdir -p "$WORK/gnupg"
chmod 700 "$WORK/gnupg"
CXX=/usr/bin/clang++
INCLUDES=(-I "$ROOT/Sources/CEncryptMsg/include" -I "$ROOT/vendor/include" -I "$ROOT/vendor/include/encryptmsg")
LIBS=("$ROOT/vendor/lib/libencryptmsg.a" "$ROOT/vendor/lib/libbotan-3.a" -lz -lbz2 -framework Security -framework CoreFoundation)

echo "==> compiling bridge and tests"
"$CXX" -std=c++20 -O2 "${INCLUDES[@]}" -c "$ROOT/Sources/CEncryptMsg/EncryptMsgBridge.cpp" -o "$WORK/bridge.o"
"$CXX" -std=c++20 -O2 "${INCLUDES[@]}" -c "$ROOT/bridge-tests/bridge_tests.cpp" -o "$WORK/tests.o"
"$CXX" -std=c++20 -O2 "${INCLUDES[@]}" -c "$ROOT/bridge-tests/bridge_cli.cpp" -o "$WORK/cli.o"
"$CXX" -o "$WORK/tests" "$WORK/tests.o" "$WORK/bridge.o" "${LIBS[@]}"
"$CXX" -o "$WORK/bridge_cli" "$WORK/cli.o" "$WORK/bridge.o" "${LIBS[@]}"

echo "==> C ABI round trips / integrity / format rejection"
"$WORK/tests"

PASS='interop-密码-2026'
printf 'frontmatter: 中文 emoji 😀\n# Heading\n\n```swift\nlet x = "你好"\n```\n' > "$WORK/plain.md"

export GNUPGHOME="$WORK/gnupg"
echo "==> GnuPG -> app"
exec 3<<<"$PASS"
gpg --batch --yes --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3 \
  --rfc4880 --symmetric --cipher-algo AES256 --s2k-digest-algo SHA256 \
  --s2k-mode 3 --s2k-count 1015808 --compress-algo zlib \
  -o "$WORK/gpg.gpg" "$WORK/plain.md"
printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/gpg.gpg" "$WORK/from-gpg.md"
cmp "$WORK/plain.md" "$WORK/from-gpg.md"

echo "==> app -> GnuPG"
printf '%s\n' "$PASS" | "$WORK/bridge_cli" encrypt "$WORK/plain.md" "$WORK/app.gpg"
exec 3<<<"$PASS"
gpg --batch --yes --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3 \
  --decrypt -o "$WORK/from-app.md" "$WORK/app.gpg"
cmp "$WORK/plain.md" "$WORK/from-app.md"

echo "==> packet parameters from GnuPG's own parser"
exec 3<<<"$PASS"
gpg --batch --pinentry-mode loopback --passphrase-fd 3 --list-packets "$WORK/app.gpg" > "$WORK/packets.txt" 2>&1
grep -q 'cipher 9' "$WORK/packets.txt"
grep -q 's2k 3' "$WORK/packets.txt"
grep -q 'hash 8' "$WORK/packets.txt"
grep -q 'count 1015808' "$WORK/packets.txt"
grep -q 'mdc: 2' "$WORK/packets.txt"
grep -q 'compressed packet: algo=2' "$WORK/packets.txt"
sed -n '1,12p' "$WORK/packets.txt"

echo "==> wrong password / tamper / truncation / plaintext-in-.gpg"
if printf '%s\n' 'definitely wrong' | "$WORK/bridge_cli" decrypt "$WORK/gpg.gpg" "$WORK/wrong.out" 2>"$WORK/wrong.err"; then
  echo "wrong password was accepted" >&2; exit 1
fi
[[ ! -e "$WORK/wrong.out" ]]
grep -qi 'incorrect\|damaged' "$WORK/wrong.err"

cp "$WORK/app.gpg" "$WORK/tampered.gpg"
printf '\x01' | dd of="$WORK/tampered.gpg" bs=1 seek=40 conv=notrunc status=none
if printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/tampered.gpg" "$WORK/tampered.out" 2>/dev/null; then
  echo "tampered ciphertext was accepted" >&2; exit 1
fi
[[ ! -e "$WORK/tampered.out" ]]

head -c 30 "$WORK/app.gpg" > "$WORK/truncated.gpg"
if printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/truncated.gpg" "$WORK/truncated.out" 2>/dev/null; then
  echo "truncated ciphertext was accepted" >&2; exit 1
fi
[[ ! -e "$WORK/truncated.out" ]]

printf 'this is plaintext, not OpenPGP\n' > "$WORK/plain.gpg"
if printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/plain.gpg" "$WORK/plain.out" 2>/dev/null; then
  echo "plaintext .gpg was accepted" >&2; exit 1
fi
[[ ! -e "$WORK/plain.out" ]]

echo "==> public-key message rejection"
exec 3<<<""
gpg --batch --yes --pinentry-mode loopback --passphrase '' \
  --quick-generate-key 'Flo GPG Test <flo-gpg-test@example.invalid>' default default never >/dev/null 2>&1
gpg --batch --yes --trust-model always --recipient flo-gpg-test@example.invalid \
  --output "$WORK/public.gpg" --encrypt "$WORK/plain.md"
if printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/public.gpg" "$WORK/public.out" 2>"$WORK/public.err"; then
  echo "public-key message was accepted" >&2; exit 1
fi
grep -qi 'unsupported' "$WORK/public.err"
[[ ! -e "$WORK/public.out" ]]

echo "==> ASCII armor rejection"
exec 3<<<"$PASS"
gpg --batch --yes --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3 \
  --rfc4880 --armor --symmetric -o "$WORK/armor.asc" "$WORK/plain.md"
if printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/armor.asc" "$WORK/armor.out" 2>"$WORK/armor.err"; then
  echo "armored message was accepted" >&2; exit 1
fi
grep -qi 'unsupported' "$WORK/armor.err"

echo "==> EncryptPad (password-only .gpg, optional)"
ENCRYPTCLI="${ENCRYPTCLI:-$(command -v encryptcli 2>/dev/null || true)}"
if [[ -n "$ENCRYPTCLI" && -x "$ENCRYPTCLI" ]]; then
  exec 3< <(printf '%s' "$PASS")
  "$ENCRYPTCLI" -e --pwd-fd 3 -f -o "$WORK/ep.gpg" "$WORK/plain.md"
  printf '%s\n' "$PASS" | "$WORK/bridge_cli" decrypt "$WORK/ep.gpg" "$WORK/ep-from-app.md"
  cmp "$WORK/plain.md" "$WORK/ep-from-app.md"
  printf '%s\n' "$PASS" | "$WORK/bridge_cli" encrypt "$WORK/plain.md" "$WORK/ep-app.gpg"
  exec 3< <(printf '%s' "$PASS")
  "$ENCRYPTCLI" -d --pwd-fd 3 -f -o "$WORK/ep-to-app.md" "$WORK/ep-app.gpg"
  cmp "$WORK/plain.md" "$WORK/ep-to-app.md"
  echo "EncryptPad interop: PASS ($ENCRYPTCLI)"
else
  echo "SKIP: set ENCRYPTCLI=/path/to/encryptcli to run EncryptPad interop."
fi

echo "bridge + GnuPG interop tests: PASS"
