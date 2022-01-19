"""Dependencies of TypeScript/JavaScript Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_javascript_deps():
    """Load dependencies of TypeScript/JavaScript Tink."""
    if not native.existing_rule("build_bazel_rules_nodejs"):
        # Release from 2021-10-11
        http_archive(
            name = "build_bazel_rules_nodejs",
            urls = ["https://github.com/bazelbuild/rules_nodejs/releases/download/4.4.0/rules_nodejs-4.4.0.tar.gz"],
            sha256 = "c9c5d60d6234d65b06f86abd5edc60cadd1699f739ee49d33a099d2d67eb1ae8",
        )

    if not native.existing_rule("io_bazel_rules_closure"):
        # Tag from 2021-06-11
        http_archive(
            name = "io_bazel_rules_closure",
            strip_prefix = "rules_closure-0.12.0",
            urls = ["https://github.com/bazelbuild/rules_closure/archive/0.12.0.tar.gz"],
            sha256 = "9498e57368efb82b985db1ed426a767cbf1ba0398fd7aed632fc3908654e1b1e",
        )

    if not native.existing_rule("io_bazel_rules_webtesting"):
        # Release from 2021-09-15
        http_archive(
            name = "io_bazel_rules_webtesting",
            urls = ["https://github.com/bazelbuild/rules_webtesting/releases/download/0.3.5/rules_webtesting.tar.gz"],
            sha256 = "e9abb7658b6a129740c0b3ef6f5a2370864e102a5ba5ffca2cea565829ed825a",
        )

    if not native.existing_rule("bazel_skylib"):
        # Release from 2021-09-27
        http_archive(
            name = "bazel_skylib",
            urls = [
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
            ],
            sha256 = "c6966ec828da198c5d9adbaa94c05e3a1c7f21bd012a0b29ba8ddbccb2c93b0d",
        )
