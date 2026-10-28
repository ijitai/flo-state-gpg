// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "FloStateNative",
    platforms: [.macOS(.v14), .iOS(.v17)],
    products: [
        .executable(name: "FloStateNative", targets: ["FloStateNative"]),
        .library(name: "FloCore", targets: ["FloCore"]),
        .library(name: "FloKit", targets: ["FloKit"]),
        .executable(name: "GPGTestRunner", targets: ["GPGTestRunner"]),
    ],
    dependencies: [
        // In-app updates (pinned; bump deliberately — scripts/release.sh uses its bin/ tools).
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
    ],
    targets: [
        // evpo/libencryptmsg + Botan 3, statically linked for macOS arm64. The
        // C ABI (Sources/CEncryptMsg) catches every C++ exception.
        .binaryTarget(name: "FloEncryptMsgVendor", path: "vendor/FloEncryptMsgVendor.xcframework"),
        .target(name: "CEncryptMsg", dependencies: ["FloEncryptMsgVendor"], path: "Sources/CEncryptMsg",
                publicHeadersPath: "include",
                cxxSettings: [.headerSearchPath("../../vendor/include"), .headerSearchPath("../../vendor/include/encryptmsg")],
                linkerSettings: [.linkedLibrary("z"), .linkedLibrary("bz2"), .linkedLibrary("c++")]),
        // Resources/<lang>.lproj: UI strings (Localizable.strings) + the localized Welcome note, copied
        // verbatim (CFBundle treats the bundle's top-level Resources/ as its resource directory).
        .target(name: "FloCore", dependencies: ["CEncryptMsg"], resources: [.copy("Resources")], swiftSettings: [.swiftLanguageMode(.v5)]),
        .target(name: "FloKit", dependencies: ["FloCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "FloStateNative", dependencies: ["FloKit", .product(name: "Sparkle", package: "Sparkle")], swiftSettings: [.swiftLanguageMode(.v5)]),
        // Shared test helpers (synthetic documents), no dependencies.
        .target(name: "FloTestSupport", path: "Tests/FloTestSupport", swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "FloCoreTests", dependencies: ["FloCore", "FloTestSupport"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "FloKitTests", dependencies: ["FloKit", "FloTestSupport"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "FloStateNativeTests", dependencies: ["FloStateNative", "FloTestSupport"], swiftSettings: [.swiftLanguageMode(.v5)]),
        // XCTest is unavailable with Command Line Tools only; this executable
        // target runs the crypto/integration checks with `swift run GPGTestRunner`.
        .executableTarget(name: "GPGTestRunner", dependencies: ["FloCore"], path: "Tests/GPGTestRunner", swiftSettings: [.swiftLanguageMode(.v5)]),
    ],
    cxxLanguageStandard: .cxx20
)
