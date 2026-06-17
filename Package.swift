// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MirketAuthSDK",
    platforms: [
        // The async/await wrapper compiles only on iOS 13+ (gated with @available).
        // The core completion-handler APIs work on iOS 11+.
        .iOS(.v11)
    ],
    products: [
        .library(
            name: "MirketAuthSDK",
            targets: ["MirketAuthSDK"]
        ),
    ],
    targets: [
        .target(
            name: "MirketAuthSDK"
        ),
        .testTarget(
            name: "MirketAuthSDKTests",
            dependencies: ["MirketAuthSDK"]
        ),
    ]
)
