"""Dependencies of TypeScript/JavaScript Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_javascript_deps():
    """Load dependencies of TypeScript/JavaScript Tink."""

    # proto
    # proto_library, cc_proto_library and java_proto_library rules implicitly depend
    # on @com_google_protobuf//:proto, @com_google_protobuf//:cc_toolchain and
    # @com_google_protobuf//:java_toolchain, respectively.
    # This statement defines the @com_google_protobuf repo.
    # Release from 2021-06-08
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.19.3",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip"],
            sha256 = "6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42",
        )

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

    # Basic rules we need to add to bazel.
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

    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )
