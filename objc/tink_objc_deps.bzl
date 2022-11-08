"""Dependencies of Tink ObjC."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_objc_deps():
    """Dependencies for Tink Objective C."""
    if not native.existing_rule("build_bazel_rules_apple"):
        # Release from 2022-09-16.
        http_archive(
            name = "build_bazel_rules_apple",
            sha256 = "90e3b5e8ff942be134e64a83499974203ea64797fd620eddeb71b3a8e1bff681",
            url = "https://github.com/bazelbuild/rules_apple/releases/download/1.1.2/rules_apple.1.1.2.tar.gz",
        )
    if not native.existing_rule("build_bazel_rules_swift"):
        # Release from 2022-09-16.
        http_archive(
            name = "build_bazel_rules_swift",
            sha256 = "51efdaf85e04e51174de76ef563f255451d5a5cd24c61ad902feeadafc7046d9",
            url = "https://github.com/bazelbuild/rules_swift/releases/download/1.2.0/rules_swift.1.2.0.tar.gz",
        )
    if not native.existing_rule("build_bazel_apple_support"):
        # Release from 2022-10-31.
        http_archive(
            name = "build_bazel_apple_support",
            sha256 = "2e3dc4d0000e8c2f5782ea7bb53162f37c485b5d8dc62bb3d7d7fc7c276f0d00",
            url = "https://github.com/bazelbuild/apple_support/releases/download/1.3.2/apple_support.1.3.2.tar.gz",
        )
