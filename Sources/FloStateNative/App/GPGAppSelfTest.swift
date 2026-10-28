import AppKit
import FloCore

/// Offscreen end-to-end smoke test for the app's document/session/window
/// plumbing. It is not a replacement for a human GUI pass: it drives the same
/// ShellModel, EditorStore, SaveEngine and DocumentStore objects the window
/// uses, with the real offscreen window controller.
///
/// The password is read from stdin, never argv or logs.
@MainActor
enum GPGAppSelfTest {
    static func run(_ args: [String]) -> Never {
        guard let wsIndex = args.firstIndex(of: "--gpg-selftest"), wsIndex + 1 < args.count,
              let dataIndex = args.firstIndex(of: "--data-dir"), dataIndex + 1 < args.count,
              let password = readLine(), !password.isEmpty else {
            FileHandle.standardError.write(Data("usage: --gpg-selftest <workspace> --data-dir <dir> (password on stdin)\n".utf8))
            exit(2)
        }
        let workspace = args[wsIndex + 1]
        let dataDir = args[dataIndex + 1]
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        Task { @MainActor in
            let code = await execute(workspace: workspace, dataDir: dataDir, password: password)
            exit(code)
        }
        app.run()
        exit(2)
    }

    static func execute(workspace: String, dataDir: String, password: String) async -> Int32 {
        var failures: [String] = []
        func check(_ ok: Bool, _ what: String) { if !ok { failures.append(what) } }
        func stage(_ s: String) { FileHandle.standardError.write(Data(("stage: " + s + "\n").utf8)) }
        stage("start")

        do {
            try FileManager.default.createDirectory(atPath: workspace, withIntermediateDirectories: true)
            let plain = workspace + "/plain.md"
            let encrypted = workspace + "/secret.md.gpg"
            let original = "# Secret\n\nhello 世界 😀\n"
            let edited = "# Secret\n\nhello 世界 😀\n\nedited through the app\n"
            try Data("# Plain\n\nplain body\n".utf8).write(to: URL(fileURLWithPath: plain))

            stage("fixture")
            let creator = DocumentStore()
            _ = try await creator.createEncryptedFile(encrypted, content: original, passphrase: password)
            creator.shutdown()

            stage("model")
            let model = ShellModel(dataDir: AppDataDirectory(baseURL: URL(fileURLWithPath: dataDir)), importLegacy: false)
            model.systemIsDark = { false }
            var alerts: [String] = []
            let wc = ShellWindowController(model: model,
                                           frame: NSRect(x: -10000, y: -10000, width: 1200, height: 800),
                                           offscreen: true)
            wc.root.opaqueBase = true
            // Keep the offscreen window alive when the encrypted tab closes so
            // later steps can exercise reopen/restore in the same model.
            model.requestWindowClose = {}
            // The controller installs the real modal prompts in wire(); replace
            // them with non-interactive answers for this offscreen test.
            model.documents.unlockPrompt = { _ in password }
            model.documents.newPassphrasePrompt = { _ in password }
            model.alert = { alerts.append($0) }
            stage("open workspace")
            await model.openWorkspace(workspace, openFile: encrypted, keepSession: false)
            wc.flush()
            stage("opened workspace")
            check(model.editor.file(encrypted)?.encryption == .encryptedUnlocked, "open encrypted document")
            check(model.editor.file(encrypted)?.content == original, "decrypted content reaches the editor")
            check(alerts.isEmpty, "no alerts while opening: \(alerts)")

            model.editor.updateContent(encrypted, edited)
            check(model.editor.file(encrypted)?.isDirty == true, "edit marks dirty")
            stage("flush")
            let saved = await model.flushDirtyFiles()
            check(saved, "flush succeeds")
            check(model.editor.file(encrypted)?.isDirty == false, "flush clears dirty")
            let reader = DocumentStore()
            reader.unlockPrompt = { _ in password }
            var savedContent: String?
            do { savedContent = try await reader.read(encrypted, promptIfNeeded: true).content }
            catch { failures.append("reading saved ciphertext: \(error)") }
            reader.shutdown()
            check(savedContent == edited, "re-encrypted disk content is the edited text")

            if let tab = model.editor.tabs.first(where: { $0.location.primaryPath == encrypted }) {
                model.editor.closeTab(tab.id)
            }
            check(!model.documents.hasSession(encrypted), "closing the encrypted tab releases its session")

            stage("reopen")
            try? await model.editor.openFileInTabOrFocus(encrypted)
            check(model.editor.file(encrypted)?.encryption == .encryptedUnlocked, "re-open after close prompts again and unlocks")
            check(model.editor.file(encrypted)?.content == edited, "re-open sees the saved text")

            stage("open failures")
            let wrongFile = workspace + "/wrong-password.md.gpg"
            let cancelFile = workspace + "/cancel.md.gpg"
            let scratch = DocumentStore()
            _ = try await scratch.createEncryptedFile(wrongFile, content: "wrong", passphrase: password)
            _ = try await scratch.createEncryptedFile(cancelFile, content: "cancel", passphrase: password)
            scratch.shutdown()
            model.documents.unlockPrompt = { _ in "definitely wrong" }
            try? await model.editor.openFileInTabOrFocus(wrongFile)
            check(model.editor.file(wrongFile) == nil, "wrong password does not create a document")
            check(alerts.contains(where: { $0.contains("Couldn't open") }), "wrong password shows an error alert")
            let alertCount = alerts.count
            model.documents.unlockPrompt = { _ in nil }
            try? await model.editor.openFileInTabOrFocus(cancelFile)
            check(model.editor.file(cancelFile) == nil, "cancel does not create a document")
            check(alerts.count == alertCount, "cancel is not reported as an error")
            model.documents.unlockPrompt = { _ in password }

            stage("plain")
            try? await model.editor.openFileInTabOrFocus(plain)
            model.editor.updateContent(plain, "# Plain\n\nchanged\n")
            check(await model.flushDirtyFiles(), "plain flush succeeds")
            check((try? String(contentsOfFile: plain, encoding: .utf8)) == "# Plain\n\nchanged\n", "plain save regression")

            stage("session restore")
            model.sessionAutosaver.saveNow()
            let restored = ShellModel(dataDir: AppDataDirectory(baseURL: URL(fileURLWithPath: dataDir)), importLegacy: false)
            restored.systemIsDark = { false }
            var prompted = false
            restored.documents.unlockPrompt = { _ in prompted = true; return password }
            restored.alert = { alerts.append($0) }
            await restored.openWorkspace(workspace, keepSession: true)
            check(restored.editor.file(encrypted)?.encryption == .encryptedLocked, "session restores encrypted tab locked")
            check(restored.editor.file(encrypted)?.content == "", "locked restore has no plaintext")
            check(!prompted, "session restore does not prompt")

            restored.unlock(encrypted)
            var unlocked = false
            for _ in 0..<120 {
                if restored.editor.file(encrypted)?.encryption == .encryptedUnlocked { unlocked = true; break }
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            check(unlocked, "locked tab unlocks on demand")
            check(prompted, "unlock prompt ran")
            check(restored.editor.file(encrypted)?.content == edited, "unlocked content matches disk")

            stage("workspace reuse")
            await model.closeWorkspaceAfterSaving()
            check(model.root == nil, "close workspace clears the root")
            await model.openWorkspace(workspace, openFile: encrypted, keepSession: false)
            check(model.editor.file(encrypted)?.encryption == .encryptedUnlocked,
                  "same model can open encrypted documents after a workspace close")

            stage("closing")
            model.windowWillClose()
            restored.windowWillClose()
            check(!model.documents.hasSession(encrypted), "window close releases secrets")
            check(!restored.documents.hasSession(encrypted), "restored window close releases secrets")
            _ = wc
        } catch {
            failures.append("threw: \(error)")
        }

        if failures.isEmpty {
            print("GPGAPP SELFTEST: PASS")
            return 0
        }
        for f in failures { print("GPGAPP SELFTEST FAIL: \(f)") }
        return 1
    }
}
