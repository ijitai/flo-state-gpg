import Foundation
import Darwin

/// Where the native app keeps its app-data files. Same file names and JSON
/// formats as the Tauri app's `{app_data}` dir so they are interchangeable.
public struct AppDataDirectory {
    public static let configFileName = "config"
    public static let sessionsFileName = "sessions.json"
    public static let recentWorkspacesFileName = "recent_workspaces.json"
    public static let recentFilesFileName = "recent_files.json"

    /// Files copied from the web app's data dir on first run.
    public static let importedFileNames = [configFileName, sessionsFileName, recentWorkspacesFileName, recentFilesFileName]

    public let baseURL: URL

    public init(baseURL: URL) { self.baseURL = baseURL }

    public static var defaultBaseURL: URL {
        applicationSupport.appendingPathComponent("FloStateGPG", isDirectory: true)
    }

    /// The Tauri app's data dir (bundle identifier `com.writer-computer`).
    public static var legacyBaseURL: URL {
        applicationSupport.appendingPathComponent("com.writer-computer", isDirectory: true)
    }

    private static var applicationSupport: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
    }

    public var configURL: URL { baseURL.appendingPathComponent(Self.configFileName) }
    public var sessionsURL: URL { baseURL.appendingPathComponent(Self.sessionsFileName) }
    public var recentWorkspacesURL: URL { baseURL.appendingPathComponent(Self.recentWorkspacesFileName) }
    public var recentFilesURL: URL { baseURL.appendingPathComponent(Self.recentFilesFileName) }

    /// Creates the directory. On first run (directory absent) copies the web
    /// app's files over from `legacyURL` when it exists. Returns the names of
    /// the files imported (empty when nothing was imported).
    @discardableResult
    public func prepare(importingFrom legacyURL: URL? = AppDataDirectory.legacyBaseURL) throws -> [String] {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: baseURL.path, isDirectory: &isDir), isDir.boolValue { return [] }
        try fm.createDirectory(at: baseURL, withIntermediateDirectories: true)
        guard let legacy = legacyURL, fm.fileExists(atPath: legacy.path) else { return [] }
        var imported: [String] = []
        for name in Self.importedFileNames {
            let src = legacy.appendingPathComponent(name)
            guard fm.fileExists(atPath: src.path) else { continue }
            let dst = baseURL.appendingPathComponent(name)
            do {
                try fm.copyItem(at: src, to: dst)
                imported.append(name)
            } catch {
                continue
            }
        }
        return imported
    }
}

/// Write-to-temp + rename in the same directory. When `url` is a symbolic
/// link, the file it points to is replaced and the link is kept (renaming
/// over the link itself would turn it into a detached copy).
enum AtomicFile {
    /// Writes ciphertext to a unique, same-directory temporary file with
    /// owner-only permissions, fsyncs it, then atomically renames it over the
    /// target. On any failure the temporary file is removed. `data` must
    /// already be encrypted: nothing here knows how to encrypt.
    static func writeSecure(_ data: Data, to url: URL, tempName: String) throws {
        let resolved = WorkspaceFS.symlinkTarget(url.path).map { URL(fileURLWithPath: $0) } ?? url
        let tmp = resolved.deletingLastPathComponent().appendingPathComponent(tempName)
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        _ = fchmod(fd, 0o600)
        var closed = false
        var committed = false
        defer {
            if !closed { _ = close(fd) }
            if !committed { _ = unlink(tmp.path) }
        }
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let written = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                if written == 0 { throw POSIXError(.EIO) }
                offset += written
            }
        }
        if fsync(fd) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        if close(fd) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        closed = true
        if rename(tmp.path, resolved.path) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        committed = true
    }

    static func write(_ data: Data, to url: URL, tempName: String) throws {
        let url = WorkspaceFS.symlinkTarget(url.path).map { URL(fileURLWithPath: $0) } ?? url
        let tmp = url.deletingLastPathComponent().appendingPathComponent(tempName)
        try data.write(to: tmp)
        if rename(tmp.path, url.path) != 0 {
            let err = errno
            try? FileManager.default.removeItem(at: tmp)
            throw POSIXError(POSIXErrorCode(rawValue: err) ?? .EIO)
        }
    }
}
