"""Dependencies of Tink ObjC."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_objc_deps():
    """Dependencies for Tink Objective C."""
    if not native.existing_rule("build_bazel_rules_apple"):
        # Release from 2022-12-21.
        http_archive(
            strip_prefix = "rules_apple-2.0.0",
            name = "build_bazel_rules_apple",
            sha256 = "58fef2369c53b0d9a75441bc40489b586a7ccce24335c9b51ccfa7265623aeb4",
            url = "https://github.com/bazelbuild/rules_apple/archive/refs/tags/2.0.0.zip",
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

    # Currently required by ios_unit_test
    if not native.existing_rule("xctestrunner"):
        # Release from 2021-11-01.
        http_archive(
            name = "xctestrunner",
            strip_prefix = "xctestrunner-0.2.15",
            sha256 = "03ce1088f74d85e23d14a09e533383bd06368d2b453c962e6ce66f80b833feae",
            url = "https://github.com/google/xctestrunner/archive/refs/tags/0.2.15.zip",
        )

    # Subpar is a utility for creating self-contained python executables. It is designed to work well with Bazel.
    # Currently required by @xctestrunner
    if not native.existing_rule("subpar"):
        # Release from 2019-05-14.
        http_archive(
            name = "subpar",
            strip_prefix = "subpar-2.0.0",
            sha256 = "8876244a984d75f28b1c64d711b6e5dfab5f992a3b741480e63cfc5e26acba93",
            url = "https://github.com/google/subpar/archive/refs/tags/2.0.0.zip",
        )
