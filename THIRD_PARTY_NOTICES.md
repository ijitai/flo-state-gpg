# Third-party notices

This distribution is **Flo State GPG**, a modified version (fork) of
**Flo-State Native**. It vendors the native crypto dependencies needed to build
offline and includes their license texts in [`Licenses/`](Licenses/). The
packaged app copies `LICENSE`, `NOTICE`, this file and `Licenses/` into
`Contents/Resources/`.

## Flo State GPG modifications

* Copyright (C) 2026 Flo State GPG contributors.
* License: **GPL-3.0-or-later**, inherited from Flo-State Native. See
  [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
* The corresponding source for this build is this repository.

## Flo-State Native

* Upstream: https://github.com/Altimor/flo-state
* Commit used: `5e36d503395c4e58b3ebe4d3d9e740d45fa4b4b0` (0.1.18)
* Copyright (C) Altimor and Flo-State Native contributors.
* License: GNU GPL v3.0 or later — see [`LICENSE`](LICENSE).
* Flo-State is itself a derivative work of
  [writer-computer](https://github.com/joelbqz/writer-computer) by Joel
  (`@joelbqz`) and contributors, licensed GPL-3.0. Its behaviour, settings
  schema, themes and some bundled assets remain under that attribution.

## evpo/libencryptmsg

* Upstream: https://github.com/evpo/libencryptmsg
* Commit used: `1cfa8db9951a86ebe283cd3ecb1c88e6914ae4f0`
* Vendored at `vendor/src/libencryptmsg/`.
* Copyright (c) 2018, Evgeny Pokhilko <https://evpo.net/libencryptmsg>.
* License: Simplified BSD / BSD-2-Clause.
* Full text: [`Licenses/libencryptmsg-BSD-2-Clause.txt`](Licenses/libencryptmsg-BSD-2-Clause.txt).
* Bundled dependencies:
  * plog (MIT, Copyright (c) 2022 Sergey Podobry) —
    [`Licenses/plog-MIT.txt`](Licenses/plog-MIT.txt).
  * state_machine (BSD-2-Clause, Copyright (c) 2018 Evgeny Pokhilko) —
    [`Licenses/state_machine-BSD-2-Clause.txt`](Licenses/state_machine-BSD-2-Clause.txt).
  * STLplus (BSD-style, Copyright Andy Rushton) —
    [`Licenses/STLplus-LICENSE.html`](Licenses/STLplus-LICENSE.html).

## Botan

* Upstream: https://github.com/randombit/botan
* Version: `3.13.0` (tarball SHA-256
  `9fbff1cd4fe7caff9bc146304dabf551e05a8beefdf03062b63d02cbb61f2e22`)
* Vendored at `vendor/src/botan/`.
* Copyright (C) 1999-2026 The Botan Authors.
* License: Simplified BSD / BSD-2-Clause.
* Full text: [`Licenses/Botan-BSD-2-Clause.txt`](Licenses/Botan-BSD-2-Clause.txt).

## Sparkle

* Upstream: https://github.com/sparkle-project/Sparkle
* Version: `2.10.0` (SwiftPM dependency; see `Package.resolved`)
* License: MIT-style Sparkle license, including its external notices.
* Full text: [`Licenses/Sparkle-LICENSE.txt`](Licenses/Sparkle-LICENSE.txt).

## Bundled web assets from upstream

KaTeX, CodeMirror 6/Lezer, beautiful-mermaid/elkjs/entities, DOMPurify and the
CommonMark/GFM examples retain their MIT, BSD-2-Clause, EPL-2.0 and
MPL-2.0-or-Apache-2.0 terms. Component locations and licenses are listed in
the upstream License section of [`README.md`](README.md); the minified builds
were produced from the npm packages pinned by writer-computer's lockfile.

## EncryptPad

EncryptPad (https://github.com/evpo/EncryptPad, GPLv2+) was used only as a
test/reference implementation for libencryptmsg's password-only `.gpg` format.
It is not linked into, vendored in, or redistributed with this build.
