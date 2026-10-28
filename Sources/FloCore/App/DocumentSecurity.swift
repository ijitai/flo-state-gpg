import Foundation
import Darwin
import CEncryptMsg

/// Where a document's plaintext currently lives.
///
/// This is part of the open-document state (`OpenFile.encryption`), not a
/// property inferred from the file extension at save time. A locked encrypted
/// document has no plaintext in memory and can never be saved as plain text.
public enum DocumentEncryption: String, Equatable, Sendable {
    case plaintext
    /// `.gpg` restored with the session (e.g. after relaunch) but not unlocked.
    case encryptedLocked
    /// `.gpg` decrypted and integrity-verified in this process.
    case encryptedUnlocked

    public var isEncrypted: Bool { self != .plaintext }
}

/// Errors surfaced to the user. Wrong password and ciphertext corruption are
/// deliberately one case: libencryptmsg cannot distinguish them reliably.
public enum DocumentAccessError: Error, Equatable, LocalizedError {
    case locked
    case cancelled
    case badPassphraseOrCorrupt
    case unsupportedFormat
    case missingIntegrity
    case notUTF8
    case missingSession
    case emptyPassphrase
    case passphraseMismatch
    case io(String)

    public var errorDescription: String? {
        switch self {
        case .locked:
            return L("This document is locked. Enter its password to unlock it.")
        case .cancelled:
            return L("The password prompt was cancelled.")
        case .badPassphraseOrCorrupt:
            return L("The password is incorrect, or the file is damaged.")
        case .unsupportedFormat:
            return L("This is not a supported password-encrypted OpenPGP message.")
        case .missingIntegrity:
            return L("This OpenPGP message has no integrity protection and was not opened.")
        case .notUTF8:
            return L("The decrypted content is not valid UTF-8 Markdown.")
        case .missingSession:
            return L("The encryption key for this document is no longer available. Save was blocked to avoid writing plaintext.")
        case .emptyPassphrase:
            return L("The password cannot be empty.")
        case .passphraseMismatch:
            return L("The passwords do not match.")
        case let .io(message):
            return L("File error: %@", message)
        }
    }
}

/// One document's OpenPGP passphrase, cached in Botan's secure memory inside
/// the C++ bridge. Swift never receives the passphrase back after creation.
public final class EncryptMsgSession: @unchecked Sendable {
    private var handle: OpaquePointer?
    private let lock = NSLock()

    public init(passphrase: String) throws {
        guard !passphrase.isEmpty else { throw DocumentAccessError.emptyPassphrase }
        var bytes = Array(passphrase.utf8)
        defer {
            bytes.withUnsafeMutableBytes { raw in
                if let base = raw.baseAddress { memset(base, 0, raw.count) }
            }
        }
        var session: OpaquePointer?
        let result: em_result = bytes.withUnsafeBufferPointer { buffer in
            em_session_create(buffer.baseAddress, buffer.count, &session)
        }
        guard result == EM_OK, let session else {
            throw Self.error(for: result)
        }
        handle = session
    }

    deinit { close() }

    /// Copies the cached passphrase into an independent session. The source
    /// session stays valid; either can be wiped without affecting the other.
    public func clone() throws -> EncryptMsgSession {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw DocumentAccessError.missingSession }
        var copy: OpaquePointer?
        let result = em_session_clone(handle, &copy)
        guard result == EM_OK, let copy else { throw Self.error(for: result) }
        let session = EncryptMsgSession(adopting: copy)
        return session
    }

    private init(adopting handle: OpaquePointer) { self.handle = handle }

    /// Releases and zeroes the cached passphrase. Idempotent.
    public func close() {
        lock.lock()
        if let handle {
            em_session_free(handle)
            self.handle = nil
        }
        lock.unlock()
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let handle else { throw DocumentAccessError.missingSession }
        var output = em_buffer()
        let result: em_result = plaintext.withUnsafeBytes { raw in
            em_session_encrypt(handle, raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &output)
        }
        defer { em_buffer_free(&output) }
        guard result == EM_OK else { throw Self.error(for: result) }
        guard output.length > 0 else { return Data() }
        return Data(bytes: output.data!, count: output.length)
    }

    public func decrypt(_ ciphertext: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let handle else { throw DocumentAccessError.missingSession }
        var output = em_buffer()
        let result: em_result = ciphertext.withUnsafeBytes { raw in
            em_session_decrypt(handle, raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &output)
        }
        defer { em_buffer_free(&output) }
        guard result == EM_OK else { throw Self.error(for: result) }
        guard output.length > 0 else { return Data() }
        return Data(bytes: output.data!, count: output.length)
    }

    private static func error(for result: em_result) -> DocumentAccessError {
        switch result {
        case EM_ERR_UNSUPPORTED_FORMAT: return .unsupportedFormat
        case EM_ERR_MISSING_INTEGRITY: return .missingIntegrity
        case EM_ERR_BAD_PASSPHRASE_OR_CORRUPT: return .badPassphraseOrCorrupt
        case EM_ERR_OUT_OF_MEMORY, EM_ERR_INTERNAL, EM_OK:
            return .io(String(cString: em_result_message(result)))
        default:
            return .io(String(cString: em_result_message(result)))
        }
    }
}

/// The single read/write boundary for documents.
///
/// Plain files go through WorkspaceFS. `.gpg` files are read as ciphertext,
/// decrypted and integrity-verified off the main thread, then decoded as
/// UTF-8. Saves re-encrypt in memory first and only ever write ciphertext to
/// the temporary file and target. Sessions are keyed by path: never reused
/// across documents.
@MainActor
public final class DocumentStore {
    public typealias PassphrasePrompt = @MainActor (_ path: String) -> String?
    /// Modal native secure prompt; nil means the user cancelled.
    public var unlockPrompt: PassphrasePrompt = { _ in nil }
    /// New-password prompt (the UI asks twice and verifies equality).
    public var newPassphrasePrompt: PassphrasePrompt = { _ in nil }

    private var sessions: [String: EncryptMsgSession] = [:]
    /// Bumped whenever a document is released. A slow decrypt/write that
    /// finishes after the tab closed must not resurrect its secret.
    private var generations: [String: Int] = [:]
    private var isShutdown = false

    public init() {}

    public var cachedPaths: [String] { sessions.keys.sorted() }
    public func hasSession(_ path: String) -> Bool { sessions[path] != nil }

    /// Reads a document. Encrypted files prompt only when `promptIfNeeded` is
    /// true; session restore uses false to leave a locked placeholder.
    public func read(_ path: String, promptIfNeeded: Bool) async throws -> FileContent {
        if isShutdown { throw DocumentAccessError.cancelled }
        guard WorkspaceFS.isEncryptedPath(path) else {
            return try await Task.detached(priority: .userInitiated) {
                try WorkspaceFS.readFile(path)
            }.value
        }
        return try await readEncrypted(path, promptIfNeeded: promptIfNeeded)
    }

    private func readEncrypted(_ path: String, promptIfNeeded: Bool) async throws -> FileContent {
        if isShutdown { throw DocumentAccessError.cancelled }
        let generation = generations[path] ?? 0
        let ciphertext: Data
        do {
            ciphertext = try await Task.detached(priority: .userInitiated) {
                try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
            }.value
        } catch {
            throw DocumentAccessError.io(error.localizedDescription)
        }

        let hadSession = sessions[path] != nil
        let session: EncryptMsgSession
        if let existing = sessions[path] {
            session = existing
        } else {
            guard promptIfNeeded else { throw DocumentAccessError.locked }
            guard let passphrase = unlockPrompt(path) else { throw DocumentAccessError.cancelled }
            session = try EncryptMsgSession(passphrase: passphrase)
        }

        let plaintext: Data
        do {
            plaintext = try await Task.detached(priority: .userInitiated) {
                try session.decrypt(ciphertext)
            }.value
        } catch {
            // Never keep a session whose password failed verification.
            if hadSession { release(path) } else { session.close() }
            throw error
        }

        guard let text = String(data: plaintext, encoding: .utf8) else {
            if hadSession { release(path) } else { session.close() }
            throw DocumentAccessError.notUTF8
        }
        if isShutdown || (generations[path] ?? 0) != generation {
            session.close()
            throw DocumentAccessError.cancelled
        }
        if hadSession {
            guard sessions[path] === session else { throw DocumentAccessError.cancelled }
        } else {
            sessions[path] = session
        }
        return FileContent(path: path, content: text, modifiedAt: WorkspaceFS.modifiedTime(path),
                           encryption: .encryptedUnlocked)
    }

    /// Encrypts and atomically replaces the target. `requireEncryption` comes
    /// from the open document's state. A missing session is a hard error: this
    /// method never falls back to a plaintext write.
    public func write(_ path: String, content: String, requireEncryption: Bool) async throws {
        if isShutdown { throw DocumentAccessError.cancelled }
        if requireEncryption {
            guard WorkspaceFS.isEncryptedPath(path) else {
                // An encrypted document may not be written to a non-.gpg path
                // implicitly. Save As goes through `writeEncryptedCopy`.
                throw DocumentAccessError.missingSession
            }
            guard let session = sessions[path] else { throw DocumentAccessError.missingSession }
            let ciphertext = try await Task.detached(priority: .userInitiated) {
                try session.encrypt(Data(content.utf8))
            }.value
            try await Self.writeCiphertext(ciphertext, to: path)
        } else {
            if WorkspaceFS.isEncryptedPath(path) {
                // Extension is not the policy: an encrypted path always needs
                // an explicit encrypted write.
                throw DocumentAccessError.missingSession
            }
            try await Task.detached(priority: .userInitiated) {
                _ = try WorkspaceFS.writeFile(path, content: content)
            }.value
        }
    }

    /// Creates a new encrypted document. The plaintext is encrypted in memory
    /// before the temporary file exists; only ciphertext reaches disk.
    @discardableResult
    public func createEncryptedFile(_ path: String, content: String, passphrase: String) async throws -> EncryptMsgSession {
        if isShutdown { throw DocumentAccessError.cancelled }
        let generation = generations[path] ?? 0
        let session = try EncryptMsgSession(passphrase: passphrase)
        let ciphertext = try await Task.detached(priority: .userInitiated) {
            try session.encrypt(Data(content.utf8))
        }.value
        do {
            try await Self.writeCiphertext(ciphertext, to: path)
        } catch {
            session.close()
            throw error
        }
        if isShutdown || (generations[path] ?? 0) != generation {
            session.close()
            throw DocumentAccessError.cancelled
        }
        release(path)
        sessions[path] = session
        return session
    }

    /// Saves an encrypted copy under `target`, cloning the source document's
    /// cached passphrase so either document can later be closed independently.
    public func writeEncryptedCopy(from source: String, to target: String, content: String) async throws {
        if isShutdown { throw DocumentAccessError.cancelled }
        let generation = generations[target] ?? 0
        guard let sourceSession = sessions[source] else { throw DocumentAccessError.missingSession }
        let session = try sourceSession.clone()
        let ciphertext = try await Task.detached(priority: .userInitiated) {
            try session.encrypt(Data(content.utf8))
        }.value
        do {
            try await Self.writeCiphertext(ciphertext, to: target)
        } catch {
            session.close()
            throw error
        }
        if isShutdown || (generations[target] ?? 0) != generation {
            session.close()
            throw DocumentAccessError.cancelled
        }
        release(target)
        sessions[target] = session
    }

    /// Copies an encrypted file without decrypting it (duplicate of a locked
    /// document). The copy remains locked and no secret is created.
    public func copyCiphertext(from source: String, to target: String) async throws {
        let bytes = try await Task.detached(priority: .userInitiated) {
            try Data(contentsOf: URL(fileURLWithPath: source), options: [.mappedIfSafe])
        }.value
        try await Self.writeCiphertext(bytes, to: target)
        release(target)
    }

    /// Stores a session obtained from a successful unlock prompt.
    public func adopt(_ session: EncryptMsgSession, for path: String) {
        if isShutdown { session.close(); return }
        release(path)
        sessions[path] = session
    }

    public func moveSession(from oldPath: String, to newPath: String) {
        if let s = sessions.removeValue(forKey: oldPath) {
            release(newPath)
            sessions[newPath] = s
        }
    }

    /// Releases the per-document secret. Safe to call repeatedly.
    public func release(_ path: String) {
        generations[path, default: 0] += 1
        sessions.removeValue(forKey: path)?.close()
    }

    /// Drops every per-document secret but keeps the store usable. Used when a
    /// workspace is closed but its window may be reused for another workspace.
    public func releaseAll() {
        for path in sessions.keys { generations[path, default: 0] += 1 }
        for (_, session) in sessions { session.close() }
        sessions.removeAll()
    }

    /// Terminal shutdown (window gone / app quitting): no later read or write
    /// may recreate a secret on this store.
    public func shutdown() {
        isShutdown = true
        releaseAll()
    }

    public static func writeCiphertext(_ data: Data, to path: String) async throws {
        try await Task.detached(priority: .userInitiated) {
            do {
                try AtomicFile.writeSecure(
                    data,
                    to: URL(fileURLWithPath: path),
                    tempName: ".~\(UUID().uuidString.lowercased()).gpg.tmp")
            } catch {
                throw DocumentAccessError.io(error.localizedDescription)
            }
        }.value
    }
}
