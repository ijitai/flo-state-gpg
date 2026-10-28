# Flo State GPG — encrypted Markdown

> **核心痛点 / Why this fork**
>
> 把 Markdown 笔记放进云盘，是为了同步和随时可写；但把明文交给云盘，就还要相信它的扫描、索引、备份与运维链路。即使服务商声称不扫描用户文档，加密后让云盘只能看到密文，仍然更安心。
>
> Flo State GPG 因此只做**密码式对称加密**：打开 `.gpg` 时输入一次密码，之后继续使用原有的 Markdown 编辑、预览、快捷键和标签页；Cmd-S、自动保存、关闭和退出都由应用在后台重新加密。不引入公钥、密钥管理或额外工作流，代价是密码丢失后无法恢复；云盘仍能看到文件名、大小、修改时间等元数据。

This fork of Flo State adds transparent OpenPGP **password (symmetric)**
encryption for `.gpg` Markdown documents. It keeps the upstream editor,
AppKit/TextKit 2 rendering, shortcuts, sidebar, tabs and session model.

## Versions pinned

| Component | Version / commit |
|---|---|
| Flo-State | `5e36d503395c4e58b3ebe4d3d9e740d45fa4b4b0` (`0.1.18`, 2026-10-08) |
| evpo/libencryptmsg | `1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0` (2026-08-13) |
| Botan | `3.13.0` (tarball SHA-256 `9fbff1cd4fe7caff9bc146304dabf551e05a8beefdf03062b63d02cbb61f2e22`) |
| Sparkle | `2.10.0` (linked, but **no feed/key** in this fork) |

Botan is built with only the modules libencryptmsg needs:
`system_rng, auto_rng, sha1, sha2_32, sha2_64, aes, des, cast128, camellia,
twofish, cfb, pgp_s2k, zlib, bzip2, mem_pool, base64, crc24`.
`crc24` is required because libencryptmsg constructs its armor CRC checker even
for binary messages. libencryptmsg is compiled with `-DNDEBUG`: upstream uses
`assert()` inside its packet reader, and a truncated ciphertext otherwise
aborts the process. With `NDEBUG` the same input becomes an error return.

## Architecture

```
SwiftUI-free AppKit UI (FloStateNative)
        │
        ▼
FloCore: EditorStore / SaveEngine / DocumentStore
        │  one read/write boundary; per-document secrets
        ▼
C ABI (Sources/CEncryptMsg, CEncryptMsg.h)
        │  never lets a C++ exception cross the boundary
        ▼
evpo/libencryptmsg (static) ── Botan 3.13 (static)
```

* `DocumentStore` (`Sources/FloCore/App/DocumentSecurity.swift`) is the only
  place that decides plaintext vs. encrypted I/O. It keys sessions by document
  path and owns `EncryptMsgSession`, which wraps an opaque C session.
* `FileContent`/`OpenFile` carry a `DocumentEncryption` state
  (`.plaintext`, `.encryptedLocked`, `.encryptedUnlocked`). Save policy comes
  from that state, never from a filename check at the last moment.
* `SaveEngine` passes the document's encryption state to the writer. The writer
  encrypts on a detached task and only then writes an atomic file.
* The C++ bridge validates the outer OpenPGP framing (SKESK + SEIPD), rejects
  armoring/public-key/no-MDC messages, and returns explicit error codes. It
  caches the passphrase in `Botan::secure_vector<uint8_t>`.

## Crypto parameters for new saves

| Parameter | Value |
|---|---|
| Format | Binary OpenPGP, RFC 4880 |
| Cipher | AES-256, CFB (OpenPGP variant with resync prefix) |
| S2K | iterated + salted, type 3 |
| S2K hash | SHA-256 |
| S2K count | 1,015,808 bytes (`EncodeS2KIterations(1015808)`, encoded as `159`) |
| Integrity | RFC 4880 MDC (tag 18, SHA-1 MDC inside the encrypted packet) |
| Compression | ZLIB |
| Partial lengths | 2^16 = 64 KiB |
| Salt / IV | fresh random salt and fresh CFB prefix on every save |
| Armor | off |

The app does **not** implement, wrap, or claim:

* public-key / recipient encryption, key management or signatures;
* EncryptPad key files or EPD/WAD containers;
* SHA-256 MDC or AEAD (OCB/EAX/GCM) OpenPGP messages.

The S2K "count" encoding and MDC SHA-1 are separate mechanisms; the MDC is
SHA-1 by RFC 4880 even though the S2K hash is SHA-256.

## Opening

* `.gpg` is matched case-insensitively (`note.gpg`, `note.md.gpg`).
* Entries: Open panel, sidebar, drag & drop, recents, Finder “Open With”, and
  session restore.
* A native `NSSecureTextField`-based prompt asks for the password. Cancel is
  allowed.
* The ciphertext is decrypted off the main thread. `MessageReader::Finish`
  verifies the MDC before any plaintext is handed to the editor. A failed or
  cancelled open removes the tab (or leaves a restored tab locked); it never
  becomes an empty editable document.
* Errors are deliberately coarse: wrong password and damaged ciphertext both
  report “The password is incorrect, or the file is damaged.” Unsupported
  framing (public key, armor, no MDC, unknown algorithm) is reported as an
  unsupported format.
* Decrypted bytes must be valid UTF-8. A non-UTF-8 payload is rejected.
* Restored `.gpg` tabs start locked (🔒) with a filename and an **Unlock…**
  button; restoring a session never prompts for passwords or parses ciphertext.

## Saving

* Cmd-S, autosave, close-time flush and quit-time flush all go through the same
  writer.
* An already-open encrypted document reuses its in-process session; no password
  prompt is repeated.
* The whole Markdown text (including frontmatter and the upstream
  save-processing result) is encrypted in memory first. The temporary file and
  the target contain ciphertext only.
* Temporary file: same directory, unique `.~<uuid>.gpg.tmp`, mode `0600`,
  `O_EXCL`, write + `fsync` + `close`, then atomic `rename`; failure removes
  the temporary file.
* A missing session is a hard error. There is no plaintext fallback for a
  `.gpg` path.
* Save errors leave the original file and the dirty buffer intact. Close/quit
  waits for the save and cancels closing if it fails.
* Autosave keeps upstream’s “one write in flight; edits during a write are
  written afterwards” semantics. Close-time flush waits for the in-flight save
  before its final write.

## New / Save As / Export

* **File → New Encrypted Note…** asks for a password twice, encrypts the initial
  Markdown, and writes from the first byte as ciphertext.
* **File → Save As Encrypted Markdown…** writes a `.gpg` copy. An encrypted
  source clones its session; a plaintext source asks for a new password twice.
  The extension is forced to `.gpg`.
* **File → Export Plaintext Copy…** is the only operation that writes decrypted
  Markdown, and it requires an explicit confirmation. A `.gpg` target is
  changed to `.md` so it cannot create a plaintext file with an encrypted
  suffix.
* Rename/move preserve the extension and migrate the session. Duplicating an
  encrypted note either re-encrypts through its session or copies ciphertext;
  a plaintext body is never written to the duplicate `.gpg`.
* An ordinary new note/export never writes a `.gpg` path as plaintext.

## Password and plaintext lifecycle

* Secrets are cached per document path, in C++ `Botan::secure_vector` inside
  the bridge. Swift receives no API to read the passphrase back.
* The first password String exists transiently in Swift/AppKit for the prompt;
  it is converted to UTF-8, copied into secure memory, and the temporary byte
  array is zeroed. Swift `String`, AppKit field storage, system swap and crash
  dumps cannot be guaranteed to be wiped.
* Closing the last view of a document releases its session (when its final save
  has finished). Closing a workspace/window releases all sessions in that
  model. Quit waits for saves, then releases sessions.
* No password is stored in Keychain, config, UserDefaults, session files, logs
  or the environment. No cross-document password retry.

## Plaintext persistence boundary

* Sessions store paths and tab metadata only; encrypted documents restore
  locked.
* Recents store path/name/open time; title extraction returns `nil` for `.gpg`
  without reading it.
* Workspace content search and the file index skip `.gpg` bodies; they never
  prompt. In-editor Find still searches the currently unlocked text in memory.
* Sidebar labels show 🔒 + filename for `.gpg`; an unlocked document may show
  its in-memory title, but that title is not written to disk.
* WKWebView-based math/Mermaid rendering uses `.nonPersistent()` data stores.
* The developer `--shell-snapshot` mode refuses to capture a workspace with an
  encrypted tab open (no PNG/JSON with decrypted content or title).
* No app-managed temp/backup/cache file contains Markdown body or password.
  Tests scan an isolated tree for a unique plaintext marker and the password.

## Real compatibility range

Verified:

* GnuPG 2.5.24 ↔ app (both directions), AES256/CFB, S2K 3/SHA-256/count
  1,015,808, MDC, ZLIB (GnuPG’s `--list-packets` output is recorded by
  `scripts/test-bridge.sh`).
* EncryptPad ↔ app (both directions), including a Chinese password:
  `encryptcli` built from EncryptPad source (0.6.0.0, libencryptmsg 0.2.0.1)
  encrypted a file that the app decrypted byte-identically and opened in the
  real GUI; the app-saved file and an app-`encryptcli` round trip were decrypted
  by EncryptPad. Password was supplied through file descriptor 3 without a
  trailing newline.
* Wrong password, tamper, truncation, plaintext-in-`.gpg`, public-key message,
  ASCII armor and MDC-less packet rejection.
* Unicode/emoji/frontmatter/code/empty/1 MB+ round trips.
* Re-encryption produces different ciphertext with a fresh salt/IV.
* Multi-document passwords never cross.

Not verified / out of scope:

* EncryptPad **key files**, EPD/WAD containers, and its GUI-only features are
  not supported. Only its password-only `.gpg` mode was tested.
* Modern AEAD/OCB messages (rejected explicitly), public-key messages (rejected
  explicitly), ASCII-armored files (rejected explicitly), and any cipher/S2K
  algorithm outside the table above.
* GnuPG 2.5 on this machine ignored `--disable-mdc` and `--aead-algo ocb` when
  producing test files; MDC-less rejection is covered by a synthetic tag-9
  packet instead.

## Automated app-level smoke

`--gpg-selftest` drives the real `ShellModel`, `EditorStore`, `SaveEngine`,
`DocumentStore` and an offscreen `ShellWindowController` through: open → decrypt
→ edit → encrypted flush → close/release → reopen → session restore locked →
unlock. Password is read from stdin.

```sh
printf '%s\n' 'test-password' | "build/Flo State GPG.app/Contents/MacOS/FloStateNative" \
  --gpg-selftest /tmp/flo-gpg-selftest-ws --data-dir /tmp/flo-gpg-selftest-data
```

It prints `GPGAPP SELFTEST: PASS`. This is not a substitute for keyboard/GUI
acceptance, but it uses the same objects and window controller as the app.

## Manual acceptance

1. Build with `scripts/build-gpg.sh` and open
   `build/Flo State GPG.app`.
2. `printf '# Secret\n\nhello 世界\n' > /tmp/secret.md`
3. `gpg --symmetric --cipher-algo AES256 --s2k-digest-algo SHA256 --rfc4880 -o /tmp/secret.md.gpg /tmp/secret.md`
   (password via pinentry).
4. Open `/tmp/secret.md.gpg` with Flo State GPG; enter the password; edit;
   Cmd-S; quit; reopen; verify the ciphertext changed and GnuPG decrypts it:
   `gpg -d /tmp/secret.md.gpg`.
5. File → New Encrypted Note…, save, reopen, verify GnuPG can decrypt.
6. File → Save As Encrypted Markdown… from a plain note; verify the new file
   starts with `c3`/binary OpenPGP and not with the Markdown text.
7. Quit with unsaved edits; confirm the document is re-encrypted before exit.


## License and copyright

This fork is distributed under **GPL-3.0-or-later**, inherited from Flo-State
Native (Copyright (C) Altimor and contributors; itself a derivative work of
writer-computer by Joel and contributors, GPL-3.0). The full GPLv3 text is in
[`LICENSE`](../LICENSE); attribution and source-availability terms are in
[`NOTICE`](../NOTICE).

libencryptmsg (Copyright (c) 2018 Evgeny Pokhilko) and Botan (Copyright (C) The
Botan Authors) are statically linked under BSD-2-Clause; Sparkle is under its
MIT-style license; plog, state_machine and STLplus retain their MIT/BSD terms.
Full texts are in [`Licenses/`](../Licenses/) and
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). The packaged app includes
`Contents/Resources/LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` and the
`Licenses/` directory.
