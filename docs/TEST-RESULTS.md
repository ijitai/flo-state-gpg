# Test results — Flo State GPG

Date: 2026-10-28 (Asia/Shanghai). Host: macOS 15.8.1, arm64 (Apple M-series),
Swift 6.1.2 / Apple clang 17.0.0 from Command Line Tools (no full Xcode),
GnuPG 2.5.24. Build used the caches under `.tmp/` with
`--disable-sandbox` because this harness already runs inside a sandbox.

## 1. Upstream baseline

```sh
swift build --disable-sandbox --product FloStateNative
```

Result: **PASS** — `Build of product 'FloStateNative' complete! (126.93s)`.
Upstream commit: `5e36d503395c4e58b3ebe4d3d9e740d45fa4b4b0` (0.1.18).
Upstream warnings are pre-existing (Swift 6 concurrency/main-actor warnings).

```sh
swift test --disable-sandbox
```

Result: **NOT RUNNABLE in this environment**. The Command Line Tools SDK does
not contain `XCTest`:

```text
error: no such module 'XCTest'
```

This is an environment/toolchain limitation, not a test failure. To compensate,
`Tests/GPGTestRunner` (a normal Swift executable) and the app-level
`--gpg-selftest` were added. A machine with Xcode can run the upstream XCTest
targets as usual.

## 2. Native crypto dependencies

Built from source:

* Botan 3.13.0, static, minimal modules including `crc24`:
  `vendor/lib/libbotan-3.a`.
* libencryptmsg `1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0`, static, with
  `-DNDEBUG` and `-mmacosx-version-min=14.0`:
  `vendor/lib/libencryptmsg.a`.
* Merged archive + hand-written XCFramework:
  `vendor/lib/libFloEncryptMsgVendor.a`,
  `vendor/FloEncryptMsgVendor.xcframework/`.

Why `-DNDEBUG`: upstream libencryptmsg `assert()`s inside its packet reader;
a truncated ciphertext aborted the process in a debug build. With `NDEBUG` the
same input returns `EM_ERR_BAD_PASSPHRASE_OR_CORRUPT` and no plaintext.
`crc24` is constructed by libencryptmsg even for binary messages.

`otool -l` confirms `min os 14.0` for the static objects and the app.

## 3. Core crypto/codec tests

Command:

```sh
swift run --disable-sandbox GPGTestRunner
```

Result: **PASS** — `GPGTestRunner: all checks passed`.

Covered:

* Unicode (Chinese, emoji), frontmatter, fenced code, empty, and ~1 MB
  documents: byte-exact decrypt equality.
* Wrong password, cancel, tampered ciphertext, truncated ciphertext, trailing
  garbage, plaintext-in-`.gpg`, public-key packet, AEAD tag 20,
  MDC-less tag 9, non-UTF-8 plaintext: all rejected; no plaintext returned.
* Missing session cannot write; a plaintext write to `.gpg` is blocked even if
  the caller claims `requireEncryption: false`.
* Simulated directory write failure leaves the original bytes and the session
  intact.
* Re-encrypting the same content/password produces different ciphertext; both
  decrypt.
* Multi-document password isolation; releasing one session does not affect the
  other; a ciphertext duplicate creates no secret.
* SaveEngine: one write in flight, follow-up save carries the newest text, old
  completion does not clear the newer dirty state.
* Session restore creates `.encryptedLocked` with no prompt and no plaintext;
  closing the last tab releases the session.
* External encrypted change reloads; an undecryptable external version is
  retained and reported.
* Workspace content search and sidebar title extraction skip `.gpg`.
* Plain Markdown open/read/write regression.
* A unique plaintext marker and the password do not appear in session/recents
  or any app-managed file in the isolated test tree; no `.~`/`.tmp` residue.

## 4. GnuPG interoperability

Command: `bash scripts/test-bridge.sh` → **PASS**.

Direction 1 — GnuPG → app:

```sh
gpg --rfc4880 --symmetric --cipher-algo AES256 --s2k-digest-algo SHA256 \
  --s2k-mode 3 --s2k-count 1015808 --compress-algo zlib ...
# then the app's bridge decrypts byte-identically
```

Direction 2 — app → GnuPG:

```sh
gpg --decrypt app-made.gpg
# byte-identical to the input
```

GnuPG's own `--list-packets` on the app output:

```text
:symkey enc packet: version 4, cipher 9, aead 0, s2k 3, hash 8
    salt ..., count 1015808 (159)
:encrypted data packet:
    version: 1
        mdc: 2
:compressed packet: algo=2
```

This confirms AES-256/CFB, S2K type 3 with SHA-256 and count 1,015,808, MDC,
and ZLIB.

Also verified: public-key message rejected as unsupported, ASCII armor
rejected, wrong password/tamper/truncation rejected, no output file created on
failure. Passwords were supplied via file descriptor or stdin, not argv; a
temporary isolated `GNUPGHOME` was used.

## 5. App-level offscreen end-to-end

Command:

```sh
printf '%s\n' 'final-selftest-密码-2026' |
  "build/Flo State GPG.app/Contents/MacOS/FloStateNative" \
    --gpg-selftest /tmp/flo-selftest-ws --data-dir /tmp/flo-selftest-data
```

Result: **PASS** — `GPGAPP SELFTEST: PASS`.

It drives the real `ShellModel`, `EditorStore`, `SaveEngine`, `DocumentStore`
and an offscreen `ShellWindowController`:

1. create an encrypted fixture;
2. open workspace + encrypted file → unlock and load;
3. edit in the store → dirty;
4. flush → ciphertext on disk, dirty cleared;
5. close tab → session released;
6. reopen → prompt again and load saved text;
7. plain Markdown edit/save regression;
8. wrong password → tab not created, error alert; cancel → no error alert;
9. save session, create a second model, restore → encrypted tab is locked with
   no prompt; explicit unlock loads the text;
10. close the workspace, reopen it in the same model and unlock again (the
    store is released but not terminally shut down);
11. close windows → sessions released.

The saved ciphertext from this test was decrypted by both GnuPG (2.5.24) and
EncryptPad’s `encryptcli` to the edited text, including `hello 世界 😀` and
`edited through the app`.

## 6. Actual GUI

Launched the packaged app with a workspace containing `secret.md.gpg`:

* The window appeared; sidebar showed `🔒 secret.md` (filename, locked).
* Opening the encrypted file produced a native secure password sheet:
  “Unlock Encrypted Document”, password field, Cancel / Unlock.
* Typing the password and pressing Return unlocked the document (window title
  became `GUI Note`; rendered Markdown with `hello from GUI`).
* Pressing Cmd-S changed the ciphertext on disk (fresh salt/IV) and the file
  remained a binary OpenPGP message. This was verified by comparing bytes
  before/after and by decrypting with the bridge/GnuPG.
* A wrong/empty password produced the explicit alert:
  “Couldn't open “secret.md.gpg”: The password is incorrect, or the file is
  damaged.”

Screenshots:

* [unlock-prompt.png](screenshots/unlock-prompt.png) — native secure password sheet.
* [unlocked-markdown.png](screenshots/unlocked-markdown.png) — unlocked, rendered Markdown.
* [open-failure.png](screenshots/open-failure.png) — explicit wrong/corrupt error.
* [encryptpad-opened.png](screenshots/encryptpad-opened.png) — EncryptPad-generated `.gpg` opened and rendered in the GUI.

**GUI editing limitation:** typing arbitrary text into the editor via synthetic
CGEvents was unreliable after the secure text field had been used (macOS secure
input/accessibility restriction in this harness). The complete
edit → Cmd-S/autosave → close → reopen flow is covered by the app-level
offscreen test above; a physical keyboard manual pass remains recommended
(steps in `docs/ENCRYPTION.md`).

## 7. EncryptPad

A local EncryptPad 0.6.0.0 `.dmg` was mounted; it contains only the x86_64 Qt
GUI. To test the CLI path, EncryptPad 0.6.0.0 source (`c9967229…`, bundled
libencryptmsg 0.2.0.1) was built with `--without-qt-ui` on arm64. Its own
bundled zlib 1.2.8 needed a minimal local test-build patch for the modern SDK
(`fdopen` macro); this patch is **not** part of Flo State GPG and is not shipped.

Result: **PASS**, both directions, with ASCII and Chinese passwords:

* EncryptPad `encryptcli -e --pwd-fd 3` → app bridge decrypt: byte-identical.
* app bridge encrypt → `encryptcli -d --pwd-fd 3`: byte-identical.
* App-saved ciphertext (`--gpg-selftest`) → `encryptcli -d`: correct edited
  Markdown including Chinese/emoji.
* EncryptPad-generated `.gpg` → real Flo State GPG GUI: password prompt,
  unlock, rendered `EncryptPad interop 中文 😀` / `heading`.

Password was passed as an exact byte sequence via fd 3 (no trailing newline).
EncryptPad key files, EPD/WAD containers and GUI-only features were not tested
and are out of scope.

## 8. Licensing

* `LICENSE` retains the upstream GNU GPL v3 text; this fork is distributed
  under GPL-3.0-or-later (see `NOTICE`).
* Upstream attribution: Flo-State Native (Altimor and contributors) and
  writer-computer (Joel and contributors).
* Static dependencies: libencryptmsg BSD-2-Clause, Botan BSD-2-Clause,
  plog MIT, state_machine BSD-2-Clause, STLplus BSD-style, Sparkle MIT-style.
  Full texts are under `Licenses/`.
* The packaged app was checked to contain `Contents/Resources/LICENSE`,
  `NOTICE`, `THIRD_PARTY_NOTICES.md`, `README.md` and `Licenses/`.
* `Info.plist` carries `NSHumanReadableCopyright`; the bundle is ad-hoc signed
  (not notarized).
