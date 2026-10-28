import Foundation
import FloCore

/// XCTest is unavailable with Command Line Tools only, so this executable
/// target carries the crypto / storage regression checks instead.
@main
@MainActor
struct GPGTestRunner {
    static func main() async {
        let runner = Runner()
        await runner.run()
        runner.finish()
    }
}

@MainActor
final class Runner {
    private var failures: [String] = []
    private let root: URL
    private let password = "correct horse 密码 🐴"
    private let wrongPassword = "wrong password"
    private let marker = "PLAINTEXT-MARKER-7f8a1c-绝密内容-DO-NOT-PERSIST"
    private let unicodeDoc: String

    init() {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("flo-state-gpg-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        unicodeDoc = """
        ---
        title: 测试文档 🚀
        date: 2026-10-28
        ---

        # 中文标题 with emoji 😀

        ```swift
        let greeting = "你好，世界"
        ```

        \(marker)

        A long paragraph: café, naïve, 日本語。 
        """
    }

    func finish() {
        if failures.isEmpty {
            print("GPGTestRunner: all checks passed")
            try? FileManager.default.removeItem(at: root)
            exit(0)
        }
        print("GPGTestRunner: \(failures.count) failure(s); kept \(root.path)")
        for f in failures { print("FAIL: \(f)") }
        exit(1)
    }

    func check(_ condition: Bool, _ label: String) {
        if !condition { failures.append(label) }
    }

    func checkEqual<T: Equatable>(_ a: T, _ b: T, _ label: String) {
        if a != b { failures.append("\(label): \(a) != \(b)") }
    }

    func expectError<T>(_ label: String, _ expected: DocumentAccessError,
                        _ body: () async throws -> T) async {
        do {
            _ = try await body()
            failures.append("\(label): expected \(expected), got success")
        } catch let e as DocumentAccessError {
            if e != expected { failures.append("\(label): expected \(expected), got \(e)") }
        } catch {
            failures.append("\(label): expected \(expected), got \(error)")
        }
    }

    func expectIOError<T>(_ label: String, _ body: () async throws -> T) async {
        do {
            _ = try await body()
            failures.append("\(label): expected an I/O error, got success")
        } catch DocumentAccessError.io(_) {
        } catch {
            failures.append("\(label): expected an I/O error, got \(error)")
        }
    }

    func run() async {
        await testCodecRoundTrips()
        await testOpenFailures()
        await testSavePolicy()
        await testEncryptedCopyAndIsolation()
        await testAsyncSaveEngine()
        await testRestoreLockedAndRelease()
        await testWatcher()
        await testSearchAndTitles()
        await testPlainRegression()
        testPlaintextPersistenceBoundary()
    }

    // MARK: helpers

    func path(_ name: String) -> String {
        root.appendingPathComponent(name).path
    }

    func writeRaw(_ p: String, _ data: Data) {
        try? FileManager.default.createDirectory(at: URL(fileURLWithPath: p).deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        try? data.write(to: URL(fileURLWithPath: p))
    }

    func readRaw(_ p: String) -> Data { (try? Data(contentsOf: URL(fileURLWithPath: p))) ?? Data() }

    func makeStore(password: String? = nil) -> DocumentStore {
        let store = DocumentStore()
        if let password = password { store.unlockPrompt = { _ in password } }
        store.newPassphrasePrompt = { _ in password }
        return store
    }

    func findFiles(_ dir: URL) -> [URL] {
        guard let e = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey]) else { return [] }
        var out: [URL] = []
        for case let u as URL in e {
            if (try? u.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true { out.append(u) }
        }
        return out
    }

    // MARK: codec

    func testCodecRoundTrips() async {
        let store = makeStore(password: password)
        let p = path("roundtrip.md.gpg")
        do {
            try await store.createEncryptedFile(p, content: unicodeDoc, passphrase: password)
        } catch { failures.append("createEncryptedFile: \(error)"); return }
        let cipher = readRaw(p)
        check(!cipher.isEmpty, "ciphertext non-empty")
        check(cipher.range(of: Data(marker.utf8)) == nil, "ciphertext contains no plaintext marker")
        check(!cipher.starts(with: Data("-----BEGIN".utf8)), "binary OpenPGP (not armor)")

        // A fresh store/process must unlock and get the exact bytes back.
        let reader = makeStore(password: password)
        do {
            let f = try await reader.read(p, promptIfNeeded: true)
            checkEqual(f.content, unicodeDoc, "unicode/frontmatter/emoji round trip")
            checkEqual(f.encryption, .encryptedUnlocked, "encryption state after read")
        } catch { failures.append("read round trip: \(error)") }

        // Empty and long documents.
        for (name, content) in [("empty.gpg", ""), ("long.gpg", String(repeating: "长文档 line 😀\n", count: 20_000))] {
            let q = path(name)
            do {
                let s = makeStore(password: password)
                try await s.createEncryptedFile(q, content: content, passphrase: password)
                let f = try await makeStore(password: password).read(q, promptIfNeeded: true)
                checkEqual(f.content, content, "round trip \(name)")
            } catch { failures.append("round trip \(name): \(error)") }
        }
    }

    func testOpenFailures() async {
        let source = makeStore(password: password)
        let p = path("failures.gpg")
        try? await source.createEncryptedFile(p, content: unicodeDoc, passphrase: password)
        let cipher = readRaw(p)

        await expectError("wrong password", .badPassphraseOrCorrupt) {
            try await self.makeStore(password: self.wrongPassword).read(p, promptIfNeeded: true)
        }
        let afterWrong = readRaw(p)
        checkEqual(afterWrong, cipher, "wrong password does not modify the file")

        // Cancel: no session, no plaintext.
        let cancel = DocumentStore()
        cancel.unlockPrompt = { _ in nil }
        await expectError("cancel unlock", .cancelled) { try await cancel.read(p, promptIfNeeded: true) }
        check(!cancel.hasSession(p), "cancelled unlock caches no session")

        // Locked restore path must not prompt or parse ciphertext.
        let locked = DocumentStore()
        locked.unlockPrompt = { _ in
            self.failures.append("locked read prompted for a password")
            return self.password
        }
        await expectError("locked read", .locked) { try await locked.read(p, promptIfNeeded: false) }

        var tampered = cipher
        tampered[40] ^= 0x40
        writeRaw(path("tampered.gpg"), tampered)
        await expectError("tampered", .badPassphraseOrCorrupt) {
            try await self.makeStore(password: self.password).read(self.path("tampered.gpg"), promptIfNeeded: true)
        }

        writeRaw(path("truncated.gpg"), cipher.prefix(31))
        await expectError("truncated", .badPassphraseOrCorrupt) {
            try await self.makeStore(password: self.password).read(self.path("truncated.gpg"), promptIfNeeded: true)
        }

        var trailing = cipher
        trailing.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])
        writeRaw(path("trailing.gpg"), trailing)
        await expectError("trailing garbage", .badPassphraseOrCorrupt) {
            try await self.makeStore(password: self.password).read(self.path("trailing.gpg"), promptIfNeeded: true)
        }

        // A plaintext file with a .gpg suffix must never be opened as text.
        writeRaw(path("plaintext.gpg"), Data("this is not OpenPGP".utf8))
        await expectError("plaintext .gpg", .badPassphraseOrCorrupt) {
            try await self.makeStore(password: self.password).read(self.path("plaintext.gpg"), promptIfNeeded: true)
        }

        // Conventional packet without MDC.
        writeRaw(path("nomdc.gpg"), Data([UInt8(0xC0 | 9), 1, 0]))
        let nomdc = makeStore(password: password)
        await expectError("missing MDC", .missingIntegrity) { try await nomdc.read(self.path("nomdc.gpg"), promptIfNeeded: true) }
        check(!nomdc.hasSession(path("nomdc.gpg")), "missing MDC caches no session")

        // Public-key packet.
        writeRaw(path("public.gpg"), Data([UInt8(0xC0 | 1), 1, 0]))
        await expectError("public key", .unsupportedFormat) {
            try await self.makeStore(password: self.password).read(self.path("public.gpg"), promptIfNeeded: true)
        }

        // Modern AEAD data packet (tag 20) is not supported.
        writeRaw(path("aead.gpg"), Data([UInt8(0xC0 | 20), 1, 0]))
        await expectError("AEAD packet", .unsupportedFormat) {
            try await self.makeStore(password: self.password).read(self.path("aead.gpg"), promptIfNeeded: true)
        }

        // Decrypted bytes that are not UTF-8 are rejected before the editor.
        if let session = try? EncryptMsgSession(passphrase: password),
           let ciphertext = try? session.encrypt(Data([0xff, 0xfe, 0xfd])) {
            try? await DocumentStore.writeCiphertext(ciphertext, to: path("utf8.gpg"))
            await expectError("non-UTF8", .notUTF8) {
                try await self.makeStore(password: self.password).read(self.path("utf8.gpg"), promptIfNeeded: true)
            }
        }
        checkEqual(readRaw(p), cipher, "failed opens leave the original intact")
    }

    // MARK: save policy

    func testSavePolicy() async {
        let p = path("save.gpg")
        let store = makeStore(password: password)
        try? await store.createEncryptedFile(p, content: unicodeDoc, passphrase: password)
        let first = readRaw(p)
        do {
            try await store.write(p, content: unicodeDoc + "\nupdated", requireEncryption: true)
        } catch { failures.append("encrypted save: \(error)"); return }
        let second = readRaw(p)
        check(first != second, "re-encryption uses a fresh salt/IV")
        check(second.range(of: Data(marker.utf8)) == nil, "saved file contains no plaintext")
        do {
            let f = try await makeStore(password: password).read(p, promptIfNeeded: true)
            checkEqual(f.content, unicodeDoc + "\nupdated", "saved plaintext round trip")
        } catch { failures.append("read saved: \(error)") }

        // Missing key blocks the write; the old bytes survive.
        let noKey = makeStore(password: nil)
        await expectError("save without session", .missingSession) {
            try await noKey.write(p, content: "should never be written", requireEncryption: true)
        }
        checkEqual(readRaw(p), second, "missing session does not overwrite")

        // Even a caller that lies about encryption cannot write plaintext over .gpg.
        await expectError("plain write to .gpg", .missingSession) {
            try await store.write(p, content: "plaintext!", requireEncryption: false)
        }
        checkEqual(readRaw(p), second, "plain write to .gpg is blocked")

        // Simulated write failure keeps the original and the session.
        let failDir = URL(fileURLWithPath: path("readonly"))
        try? FileManager.default.createDirectory(at: failDir, withIntermediateDirectories: true)
        let failPath = failDir.appendingPathComponent("x.gpg").path
        let failStore = makeStore(password: password)
        try? await failStore.createEncryptedFile(failPath, content: "before", passphrase: password)
        let before = readRaw(failPath)
        try? FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: failDir.path)
        await expectIOError("write failure") {
            try await failStore.write(failPath, content: "after", requireEncryption: true)
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: failDir.path)
        checkEqual(readRaw(failPath), before, "failed write leaves original intact")
        check(failStore.hasSession(failPath), "failed write keeps the session (edits can be retried)")

        // Save As creates ciphertext only, with an independent session.
        let copy = path("save-copy.gpg")
        do {
            try await store.writeEncryptedCopy(from: p, to: copy, content: "copy body")
            check(readRaw(copy).range(of: Data("copy body".utf8)) == nil, "save-as contains no plaintext")
            store.release(p)
            try await store.write(copy, content: "copy body 2", requireEncryption: true)
            let f = try await makeStore(password: password).read(copy, promptIfNeeded: true)
            checkEqual(f.content, "copy body 2", "save-as session survives source release")
        } catch { failures.append("save-as: \(error)") }
    }

    func testEncryptedCopyAndIsolation() async {
        let a = path("iso-a.gpg"), b = path("iso-b.gpg")
        let sa = makeStore(password: "pass A")
        let sb = makeStore(password: "pass B")
        try? await sa.createEncryptedFile(a, content: "A body", passphrase: "pass A")
        try? await sb.createEncryptedFile(b, content: "B body", passphrase: "pass B")
        sa.release(a)
        sb.release(b)

        let readerA = makeStore(password: "pass A")
        let readerB = makeStore(password: "pass B")
        do {
            checkEqual(try await readerA.read(a, promptIfNeeded: true).content, "A body", "A decrypts with A password")
            checkEqual(try await readerB.read(b, promptIfNeeded: true).content, "B body", "B decrypts with B password")
            await expectError("A with B password", .badPassphraseOrCorrupt) {
                try await self.makeStore(password: "pass B").read(a, promptIfNeeded: true)
            }
            readerA.release(a)
            await expectError("released A cannot save", .missingSession) {
                try await readerA.write(a, content: "new A", requireEncryption: true)
            }
            try await readerB.write(b, content: "new B", requireEncryption: true)
            checkEqual(try await self.makeStore(password: "pass B").read(b, promptIfNeeded: true).content,
                       "new B", "B is unaffected by releasing A")
        } catch { failures.append("isolation: \(error)") }

        // Copy without decrypting: identical ciphertext, no session at target.
        let lockedCopy = path("locked-copy.gpg")
        do {
            let cp = makeStore(password: nil)
            try await cp.copyCiphertext(from: a, to: lockedCopy)
            checkEqual(readRaw(lockedCopy), readRaw(a), "ciphertext duplicate is byte-identical")
            check(!cp.hasSession(lockedCopy), "ciphertext duplicate creates no secret")
        } catch { failures.append("ciphertext copy: \(error)") }
    }

    // MARK: save engine

    final class DeferredWriter {
        var payloads: [(path: String, content: String, encryption: DocumentEncryption)] = []
        var completions: [(Result<Void, Error>) -> Void] = []
        func write(_ path: String, _ content: String, _ encryption: DocumentEncryption,
                   _ done: @escaping @MainActor (Result<Void, Error>) -> Void) {
            payloads.append((path, content, encryption))
            completions.append(done)
        }
    }

    func testAsyncSaveEngine() async {
        let scheduler = ManualScheduler()
        let writer = DeferredWriter()
        let engine = SaveEngine(scheduler: scheduler,
                                processing: { SaveProcessing(trimTrailingWhitespace: false, insertFinalNewline: false) },
                                writer: { p, c, e, d in writer.write(p, c, e, d) })
        let files = path("engine.md")
        writeRaw(files, Data("v1".utf8))
        let store = EditorStore(reader: { p in
            FileContent(path: p, content: String(data: self.readRaw(p), encoding: .utf8) ?? "")
        }, saveEngine: engine, displayDate: { _ in nil })
        await store.openFile(files)
        store.updateContent(files, "v2")
        scheduler.advance(byMs: 1000)
        checkEqual(writer.payloads.map(\.content), ["v2"], "first save payload")
        checkEqual(writer.payloads.last?.encryption ?? .plaintext, .plaintext, "plain encryption state sent to writer")

        // Edits while the write is in flight become a follow-up save; the
        // older completion must not mark the newer text saved.
        store.updateContent(files, "v3")
        scheduler.advance(byMs: 1000)
        checkEqual(writer.payloads.map(\.content), ["v2"], "no concurrent write")
        writer.completions[0](.success(()))
        scheduler.advance(byMs: 1000)
        checkEqual(writer.payloads.map(\.content), ["v2", "v3"], "follow-up save carries newest text")
        checkEqual(store.file(files)?.isDirty, true, "newer edits stay dirty")
        writer.completions[1](.success(()))
        checkEqual(store.file(files)?.isDirty, false, "follow-up completion clears dirty")
        await store.saveEngine.waitForIdle(files)
    }

    // MARK: restore / release

    func testRestoreLockedAndRelease() async {
        let p = path("restore.gpg")
        let creator = makeStore(password: password)
        try? await creator.createEncryptedFile(p, content: "restored body", passphrase: password)
        creator.release(p)

        let store = makeStore(password: nil)
        store.unlockPrompt = { _ in
            self.failures.append("session restore prompted for a password")
            return nil
        }
        let scheduler = ManualScheduler()
        let engine = SaveEngine(scheduler: scheduler, processing: { SaveProcessing() },
                                writer: { _, _, _, d in d(.success(())) })
        let editor = EditorStore(reader: { path in try await store.read(path, promptIfNeeded: true) },
                                 saveEngine: engine, displayDate: { _ in nil })
        let tab = SessionTab(location: SerializedLocation(kind: "file", payload: [("path", .string(p))]))
        let complete = await editor.restoreSession([tab], activeIndex: 0)
        check(complete, "restore reports complete")
        checkEqual(editor.file(p)?.encryption, .encryptedLocked, "encrypted tab restored locked")
        checkEqual(editor.file(p)?.content, "", "locked tab has no plaintext")
        check(!store.hasSession(p), "restore created no session")

        editor.onFileReleased = { store.release($0) }
        store.unlockPrompt = { _ in self.password }
        do {
            let content = try await store.read(p, promptIfNeeded: true)
            editor.applyUnlocked(p, content: content)
            checkEqual(editor.file(p)?.encryption, .encryptedUnlocked, "unlock applies plaintext")
            check(store.hasSession(p), "unlock caches the session")
            editor.closeTab(editor.tabs[0].id)
            check(!store.hasSession(p), "closing the last tab releases the session")
        } catch { failures.append("unlock/close: \(error)") }
    }

    // MARK: watcher

    func testWatcher() async {
        let p = path("watch.gpg")
        let store = makeStore(password: password)
        try? await store.createEncryptedFile(p, content: "watch v1", passphrase: password)
        let scheduler = ManualScheduler()
        let engine = SaveEngine(scheduler: scheduler, processing: { SaveProcessing() },
                                writer: { _, _, _, d in d(.success(())) })
        let editor = EditorStore(reader: { path in try await store.read(path, promptIfNeeded: true) },
                                 saveEngine: engine, displayDate: { _ in nil })
        await editor.openFile(p)
        checkEqual(editor.file(p)?.content, "watch v1", "open before external change")

        // Same password, fresh salt: the watcher must decrypt and reload.
        let external = makeStore(password: password)
        try? await external.createEncryptedFile(p, content: "watch v2", passphrase: password)
        external.release(p)
        let reconciler = FileChangeReconciler(editor: editor, reader: { path in
            try await store.read(path, promptIfNeeded: false)
        })
        var failed = false
        reconciler.onReadFailure = { _, _ in failed = true }
        let changed = await reconciler.handleFileChanged(path: p, kind: .modified)
        check(changed, "external encrypted modification reloads")
        checkEqual(editor.file(p)?.content, "watch v2", "reloaded plaintext")
        check(!failed, "valid external change reports no failure")

        // External version encrypted with a different password must not clobber
        // the current buffer; the failure is reported.
        let foreign = makeStore(password: "different")
        try? await foreign.createEncryptedFile(p, content: "watch v3 foreign", passphrase: "different")
        foreign.release(p)
        let kept = await reconciler.handleFileChanged(path: p, kind: .modified)
        check(!kept, "undecryptable external version is not adopted")
        checkEqual(editor.file(p)?.content, "watch v2", "current buffer retained")
        check(failed, "undecryptable external version reports a failure")
        store.release(p)
    }

    // MARK: search / metadata

    func testSearchAndTitles() async {
        let p = path("search.gpg")
        let store = makeStore(password: password)
        try? await store.createEncryptedFile(p, content: "# Secret\n\n\(marker)\n", passphrase: password)
        store.release(p)
        let indexed = IndexedFile(path: p, relativePath: "search.gpg", name: "search.gpg", modifiedAt: 1)
        let hits = ContentSearch().search(marker, in: [indexed])
        check(hits.isEmpty, "workspace search skips .gpg without prompting")

        let title = WorkspaceFS.extractTitle(p)
        check(title == nil, "background title extraction skips .gpg")

        let entry = WorkspaceFS.fileEntry(p)
        check(entry != nil, ".gpg is listed as an openable file")
        checkEqual(entry?.title, nil, "sidebar entry has no decrypted title")
        check(WorkspaceFS.isEncryptedPath("NOTE.MD.GPG"), "uppercase .gpg recognized")
        check(!WorkspaceFS.isEncryptedPath("note.md"), ".md is not encrypted")
        check(SupportedExtensions.default.isSupported(p), "supported extensions include .gpg")
    }

    // MARK: plain regression

    func testPlainRegression() async {
        let p = path("plain.md")
        let body = "# Plain\n\n普通 Markdown 😀\n"
        writeRaw(p, Data(body.utf8))
        let store = makeStore()
        do {
            let f = try await store.read(p, promptIfNeeded: true)
            checkEqual(f.content, body, "plain read")
            checkEqual(f.encryption, .plaintext, "plain state")
            try await store.write(p, content: body + "\nmore", requireEncryption: false)
            checkEqual(String(data: readRaw(p), encoding: .utf8), body + "\nmore", "plain write")
        } catch { failures.append("plain regression: \(error)") }
    }

    // MARK: persistence boundary

    func testPlaintextPersistenceBoundary() {
        let dataDir = AppDataDirectory(baseURL: root.appendingPathComponent("appdata", isDirectory: true))
        _ = try? dataDir.prepare(importingFrom: nil)
        let encryptedPath = path("roundtrip.md.gpg")
        let store = SessionStore(appData: dataDir)
        let tab = SessionTab(location: SerializedLocation(kind: "file", payload: [("path", .string(encryptedPath))]))
        try? store.save(root: path("workspace"), tabs: [tab], activeIndex: 0)
        let recents = RecentFilesStore(appData: dataDir)
        try? recents.record(encryptedPath)
        let sessionText = String(data: readRaw(dataDir.sessionsURL.path), encoding: .utf8) ?? ""
        let recentText = String(data: readRaw(dataDir.recentFilesURL.path), encoding: .utf8) ?? ""
        check(sessionText.contains("roundtrip.md.gpg"), "session persists the path")
        check(!sessionText.contains(marker), "session stores no plaintext")
        check(!sessionText.contains(password), "session stores no password")
        check(!recentText.contains(marker), "recents store no plaintext")
        check(!recentText.contains(password), "recents store no password")

        // App-managed files in the isolated tree: no marker and no password.
        var leaked: [String] = []
        var tempLeft: [String] = []
        for f in findFiles(root) {
            let data = readRaw(f.path)
            if data.range(of: Data(marker.utf8)) != nil { leaked.append(f.path) }
            if f.lastPathComponent.hasPrefix(".~") { tempLeft.append(f.path) }
            if f.lastPathComponent.lowercased().hasSuffix(".tmp") { tempLeft.append(f.path) }
        }
        check(leaked.isEmpty, "no app-managed file contains plaintext: \(leaked)")
        check(tempLeft.isEmpty, "no temporary files left: \(tempLeft)")
    }
}
