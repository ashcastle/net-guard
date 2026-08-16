// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NetGuard",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "netguard",
            targets: ["NetGuard"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0")
    ],
    targets: [
        .executableTarget(
            name: "NetGuard",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            path: "Sources/NetGuard"
        ),
        .testTarget(
            name: "NetGuardTests",
            dependencies: ["NetGuard"],
            path: "Tests/NetGuardTests"
        )
    ]
)
