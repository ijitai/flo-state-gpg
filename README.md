# Flo State GPG

> **为什么做这个**
>
> 把 Markdown 笔记放进 iCloud、Dropbox、OneDrive 这类云盘，图的是跨设备同步和随手可写；但把明文交给云盘，意味着还要额外相信它的扫描、索引、备份和运维链路。即使服务商承诺不扫描用户文档，少一层信任总是更安心。
>
> Flo State GPG 只做一件简单的事：让云盘上的 `.gpg` 文件始终是 OpenPGP 密文。打开时输入一次密码，之后照常用 Flo State 编辑、预览、搜索和快捷键；Cmd-S、自动保存、关闭和退出都由应用在后台重新加密。云盘只能看到密文，无法直接读出标题、正文或 frontmatter。
>
> 为了“不折腾”，它刻意只实现**密码式对称加密**，不引入公钥、密钥管理、签名或额外工作流。代价是密码丢失后无法恢复；这是简单与可恢复性之间的明确取舍。云盘仍能看到文件名、大小、修改时间等元数据，本工具保护的是文档内容。

**Why this fork.** Keep Markdown in cloud storage for sync, without handing the
provider readable plaintext. Flo State GPG keeps `.gpg` files as OpenPGP
ciphertext, asks for the document password once, and transparently re-encrypts
on Cmd-S, autosave, close and quit. It deliberately implements only
password-based symmetric encryption — no public keys, key management,
signatures or extra workflow. Losing the password means losing the document;
cloud metadata such as filename, size and mtime remains visible.

This is a fork of Flo State Native, a customised build of
[writer.computer](https://github.com/joelbqz/writer-computer)'s markdown editor.
The original is a Tauri app (React + CodeMirror 6 in a web view); this one is
Swift, AppKit and TextKit 2, with no web view in the editing path.

The goal is behavioural parity with the web app: the same live-preview
rendering (syntax marks hide per line, and tables, math, Mermaid, images and
HTML blocks fold into widgets), the same editing commands and keymaps, and the
same app shell (sidebar, tabs, command palette, outline rail, settings,
find/replace). Parity is measured against the real web frontend: see
[Testing](#testing).

## This fork: Flo State GPG

`Flo State GPG` adds transparent password-based OpenPGP encryption for `.gpg`
Markdown documents on top of upstream Flo-State `5e36d50` (0.1.18). It uses
[evpo/libencryptmsg](https://github.com/evpo/libencryptmsg) + Botan 3 through a
thin C ABI. The editor, TextKit 2 rendering, shortcuts, tabs, sidebar and
session model are unchanged.

* Open `note.gpg` / `note.md.gpg` from the sidebar, Open panel, drag & drop,
  recents or Finder; enter the password once per open document.
* Cmd-S, autosave, close and quit re-encrypt to the original `.gpg` path.
* File → New Encrypted Note… / Save As Encrypted Markdown… / Export Plaintext
  Copy… (explicit only).
* Restored `.gpg` tabs are locked and never prompt during launch.
* Background title extraction, workspace search, recents and session files
  never contain decrypted body text or passwords.

Full design, crypto parameters, compatibility limits, test evidence and manual
acceptance steps: **[docs/ENCRYPTION.md](docs/ENCRYPTION.md)**.

This fork builds as `Flo State GPG.app` with bundle id `app.flostate.gpg`, its
own `~/Library/Application Support/FloStateGPG` directory, and **no Sparkle
feed or key** (an upstream binary must never replace the encryption build).

### Build (this fork)

Requires macOS 14+, Swift 6 Command Line Tools (or Xcode), Python 3 and `make`.
There is no Homebrew runtime dependency; Botan and libencryptmsg are static.

```sh
scripts/build-vendor.sh     # rebuild pinned Botan + libencryptmsg + XCFramework
scripts/build-gpg.sh        # release app -> build/Flo State GPG.app
scripts/test-gpg.sh         # core tests + app-level offscreen flow + GnuPG interop
swift run GPGTestRunner     # core crypto/document/save tests (no XCTest needed)
```

## Install (this fork)

This fork is not published as a Homebrew cask. Build it locally:

```sh
scripts/build-gpg.sh
open "build/Flo State GPG.app"
```

Do **not** install the upstream Homebrew cask / release if you need `.gpg`
support: those binaries do not contain the encryption integration. The
upstream project is still available at
[Altimor/flo-state](https://github.com/Altimor/flo-state).

## Layout

| Path | What |
|---|---|
| `Sources/FloCore` | Platform-independent core: a Swift port of `@lezer/markdown` (plus GFM and the app's extensions), editor state/transactions/history, editing commands and keymaps, the render planner (per-character styles), and the app model (settings, workspace FS, `.gitignore`, search index, sessions). |
| `Sources/FloKit` | AppKit/TextKit 2 editor: text view, layout, widgets (tables, KaTeX math, Mermaid, HTML blocks, images), find overlay, wiki-link autocomplete, paste handling. |
| `Sources/FloStateNative` | The app: window, sidebar, tabs, palette, settings, menus, plus headless CLI modes (`--snapshot`, `--batch-geometry`, `--replay-keys`, `--perf <file>`, `--fuzz-edit <file> <seed> <steps>`, `--shell-snapshot`) used by the parity harness. |
| `Tests/` | Unit and parity tests (XCTest). `Tests/FloTestSupport` generates synthetic documents. |
| `fixtures/` | Behaviour recorded from the web app (syntax trees, per-char render styles, keystroke results, find/paste/menu/wiki-link behaviour). |
| `oracle/` | The harness that runs the real web frontend headless and records or compares fixtures. |
| `tools/` | Scripts that rebuild the bundled JavaScript (code highlighting, HTML sanitizer, Mermaid) from a writer-computer checkout. |
| `docs/` | `SPEC.md` (behavioural spec of the web app), `KEYS-DEVIATIONS.md`. |

## Build

Requires macOS 14+, Swift 6 (Xcode 16 or Command Line Tools), Python 3 and
`make`. The pinned Botan/libencryptmsg sources are vendored; no Homebrew
runtime is used.

```sh
scripts/build-vendor.sh                     # static Botan + libencryptmsg + XCFramework
scripts/build-gpg.sh                        # release -> "build/Flo State GPG.app"
scripts/test-gpg.sh                         # core + app-level + GnuPG tests
swift build --product FloStateNative        # debug build (XCTest not needed)
swift run FloStateNative                    # run it (unbundled)
```

`scripts/bundle.sh` is the underlying packager; `build-gpg.sh` sets the
distinct app name, bundle id, data directory and the local SwiftPM caches.
`XCTest` is only available with a full Xcode installation; the GPG test runner
is a normal executable so it works with Command Line Tools alone.

`scripts/bundle.sh` builds with `-j ${JOBS:-2}`; set `THROTTLE` to a wrapper
command (for example `nice -n 10`) to lower its priority. The app is ad-hoc
signed unless `DEVELOPER_ID` is set (`scripts/sign.sh`).

The version is `VERSION` (CFBundleShortVersionString); the build number
(CFBundleVersion) is the git commit count.

### Updates and releases

**Updater disabled in this fork.** Sparkle 2 is still linked (and embedded) so
the upstream project structure remains intact, but `scripts/bundle.sh` writes
no `SUFeedURL`/`SUPublicEDKey`; `AppUpdater.isConfigured()` is false and no
update check can install an upstream binary that lacks encryption. The
upstream release scripts below are retained for reference only and are not
used for this fork:

```sh
scripts/test-update.sh     # upstream only
scripts/release.sh 0.2.0   # upstream only
DRY_RUN=1 scripts/release.sh
```

Notarization: set `DEVELOPER_ID="Developer ID Application: Name (TEAMID)"`
and `NOTARY_PROFILE=<profile>` (created once with `xcrun notarytool
store-credentials <profile>`). `release.sh` then signs with the hardened
runtime, notarizes and staples before zipping.

## Testing

### Unit and parity tests

```sh
swift test        # needs full Xcode (XCTest); unavailable with CLT only
scripts/test-gpg.sh
```

The parity tests replay the recorded web behaviour in `fixtures/` through the
native code and assert that nothing differs: syntax trees node for node,
render styles character by character, keystroke results, find/replace, paste,
context menu and wiki-link autocomplete. The tests need no network, no browser
and no files outside the repo; large documents are generated in code
(`Tests/FloTestSupport`).

### The oracle harness (re-recording fixtures)

`oracle/` runs the real web frontend against a mock Tauri backend
(`oracle/server.py`) and drives it through headless Chrome (CDP) or an
offscreen `WKWebView` (`oracle/wk`, the engine the Tauri app uses on macOS).

1. Check out and build writer-computer next to this repo (or anywhere, and
   point `WRITER_REPO` at it). The fixtures were recorded against the
   customised build described in `docs/SPEC.md` §5, so an unmodified
   upstream checkout will show some expected differences.

   ```sh
   git clone https://github.com/joelbqz/writer-computer ../writer-computer
   (cd ../writer-computer && vp install && vp run build -r)   # see its README; needs apps/desktop/dist
   export WRITER_REPO=$PWD/../writer-computer                # optional when it is a sibling
   ```

2. Python deps: `python3 -m venv .venv && .venv/bin/pip install websocket-client numpy pillow`.
   The WebKit driver: `swiftc -O oracle/wk/main.swift -o oracle/wk/wkoracle`
   (or use Chrome with `ORACLE_ENGINE=chrome`).

3. Generate the sample workspace the mock backend serves. It is synthetic
   (notes with headings, lists, tasks, links, wiki links, a table, code,
   frontmatter, an `Archive/` folder, an image attachment and a ~110 KB dated
   journal) and is regenerated deterministically:

   ```sh
   python3 oracle/make_sandbox.py          # -> oracle/sandbox/Sample (gitignored)
   ```

   Set `ORACLE_SANDBOX=/path/to/folder` to run the oracle on another workspace
   instead. The mock backend only ever reads and writes inside that folder.

4. Start the backend, then run a generator or a comparison:

   ```sh
   python3 oracle/server.py &              # serves $WRITER_REPO/apps/desktop/dist on :5288
   cd oracle
   python3 gen_trees.py                    # -> fixtures/trees.json
   python3 gen_render.py                   # -> fixtures/render.json
   python3 gen_keys.py                     # -> fixtures/keys.jsonl
   python3 shell_parity.py                 # app shell: web vs `FloStateNative --shell-snapshot`
   python3 geom_parity.py                  # glyph positions: web vs native
   ```

Other environment variables: `ORACLE_TMP` (scratch and screenshot output,
default `<system temp>/flo-oracle`), `NATIVE` (the `FloStateNative` binary to
compare, default the most recent debug build in the repo), `CHROME` (Chrome
executable path), `FLO_ORACLE_PORT` (backend port, default 5288; set the same
value for the server and the scripts). The server overlays the local writer-computer config
(`~/Library/Application Support/com.writer-computer/config`) on the schema
defaults; set `FLO_DEFAULT_SETTINGS=1` to ignore it.

`oracle/extract_spec.mjs` extracts the CommonMark/GFM examples from
`@lezer/markdown`'s test suite in `$WRITER_REPO/node_modules` into
`oracle/corpus-spec.json`.

## License and copyright

Flo State GPG is free software, licensed under the **GNU General Public License
v3.0 or later** (GPL-3.0-or-later), inherited from Flo State Native. This fork
does not add restrictions; modified source is distributed under the same
license. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Flo-State Native is Copyright (C) Altimor and contributors. It is a derivative
work of [writer-computer](https://github.com/joelbqz/writer-computer) by Joel
([@joelbqz](https://github.com/joelbqz)) and contributors, licensed under
GPL-3.0; its behaviour, settings schema
(`Sources/FloCore/Resources/settings.schema.json`), themes, and parts of its
source (for example the Mermaid canvas and the HTML-block sanitizer
configuration, bundled via `tools/`) are taken from that project.

The app statically links **libencryptmsg** (Copyright (c) 2018 Evgeny Pokhilko,
BSD-2-Clause) and **Botan** (Copyright (C) The Botan Authors, BSD-2-Clause).
Those BSD notices, the Sparkle/MIT notice and all native dependency license
texts are reproduced in [Licenses/](Licenses/) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and are copied into
`Flo State GPG.app/Contents/Resources/`.

Bundled or ported third-party code:

| Component | Where | License |
|---|---|---|
| [KaTeX](https://github.com/KaTeX/KaTeX) 0.16 (JS, CSS, fonts) | `Sources/FloCore/Resources/katex/` | MIT |
| [beautiful-mermaid](https://www.npmjs.com/package/beautiful-mermaid), bundled with [elkjs](https://github.com/kieler/elkjs) and [entities](https://github.com/fb55/entities) | `Sources/FloCore/Resources/mermaid/mermaid-widget.js` | MIT; elkjs: EPL-2.0; entities: BSD-2-Clause |
| [CodeMirror 6](https://codemirror.net) (`@codemirror/language`, `language-data`, `lang-*`) and [Lezer](https://lezer.codemirror.net) parsers (`@lezer/*`) | `Sources/FloCore/Resources/codehl.js` (bundled); `Sources/FloCore/Markdown` is a Swift port of `@lezer/markdown` | MIT |
| [DOMPurify](https://github.com/cure53/DOMPurify) | `Sources/FloCore/Resources/htmlblock/sanitize.js` | MPL-2.0 or Apache-2.0 |
| CommonMark/GFM spec examples from `@lezer/markdown`'s tests | `oracle/corpus-spec.json`, `fixtures/trees.json` | MIT |

The bundled JavaScript files are minified builds; their sources are the npm
packages above at the versions pinned by writer-computer's lockfile, and
`tools/*/build.sh` rebuilds them.
