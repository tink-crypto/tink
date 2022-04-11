"""Tink C++ Cloud KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_gcpkms_deps():
    """Loads dependencies for Tink C++ Cloud KMS."""

    # gRPC needs rules_apple, which in turn needs rules_swift and apple_support
    if not native.existing_rule("build_bazel_rules_apple"):
        # Release from 2021-10-29
        http_archive(
            name = "build_bazel_rules_apple",
            sha256 = "77e8bf6fda706f420a55874ae6ee4df0c9d95da6c7838228b26910fc82eea5a2",
            url = "https://github.com/bazelbuild/rules_apple/releases/download/0.32.0/rules_apple.0.32.0.tar.gz",
        )
    if not native.existing_rule("build_bazel_rules_swift"):
        # Release from 2021-10-04
        http_archive(
            name = "build_bazel_rules_swift",
            sha256 = "4f167e5dbb49b082c5b7f49ee688630d69fb96f15c84c448faa2e97a5780dbbc",
            url = "https://github.com/bazelbuild/rules_swift/releases/download/0.24.0/rules_swift.0.24.0.tar.gz",
        )
    if not native.existing_rule("build_bazel_apple_support"):
        # Release from 2021-06-11
        http_archive(
            name = "build_bazel_apple_support",
            sha256 = "76df040ade90836ff5543888d64616e7ba6c3a7b33b916aa3a4b68f342d1b447",
            url = "https://github.com/bazelbuild/apple_support/releases/download/0.11.0/apple_support.0.11.0.tar.gz",
        )

    if not native.existing_rule("com_google_googleapis"):
        # Matches version embedded in com_github_grpc_grpc from 2021-11-17
        http_archive(
            name = "com_google_googleapis",
            sha256 = "5bb6b0253ccf64b53d6c7249625a7e3f6c3bc6402abd52d3778bfa48258703a0",
            strip_prefix = "googleapis-2f9af297c84c55c8b871ba4495e01ade42476c92",
            url = "https://github.com/googleapis/googleapis/archive/2f9af297c84c55c8b871ba4495e01ade42476c92.tar.gz",
        )

    if "upb" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2021-11-17
        http_archive(
            name = "upb",
            sha256 = "7c02096dceb6b1249feaf11e4531f6bf31b9abdbd2305038349d1f1749bf88ea",
            strip_prefix = "upb-0e0de7d9f927aa888d9a0baeaf6576bbbb23bf0b",
            url = "https://github.com/protocolbuffers/upb/archive/0e0de7d9f927aa888d9a0baeaf6576bbbb23bf0b.tar.gz",
        )

    if "envoy_api" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2021-11-17
        http_archive(
            name = "envoy_api",
            sha256 = "e89d4dddbadf797dd2700ce45ee8abc82557a934a15fcad82673e7d13213b868",
            strip_prefix = "data-plane-api-20b1b5fcee88a20a08b71051a961181839ec7268",
            url = "https://github.com/envoyproxy/data-plane-api/archive/20b1b5fcee88a20a08b71051a961181839ec7268.tar.gz",
        )

    if not native.existing_rule("com_github_grpc_grpc"):
        # Release from 2021-12-15
        http_archive(
            name = "com_github_grpc_grpc",
            sha256 = "305fa696963fc4f97590931a0fcdc9c020410edd7ee31e4915bddc6bf954fbfe",
            strip_prefix = "grpc-1.43.0",
            url = "https://github.com/grpc/grpc/archive/v1.43.0.zip",
        )

    # Not used by Java Tink, but apparently needed for C++ gRPC library.
    if not native.existing_rule("io_grpc_grpc_java"):
        # Release from 2021-12-15
        http_archive(
            name = "io_grpc_grpc_java",
            sha256 = "1356886b7f9d48b606c689ab027e88456cf7ccd671615d4da55e5f10a83e71d2",
            strip_prefix = "grpc-java-1.43.0",
            url = "https://github.com/grpc/grpc-java/archive/v1.43.0.tar.gz",
        )

    if not native.existing_rule("curl"):
        # Release from 2016-05-30
        http_archive(
            name = "curl",
            url = "https://mirror.bazel.build/curl.haxx.se/download/curl-7.49.1.tar.gz",
            sha256 = "ff3e80c1ca6a068428726cd7dd19037a47cc538ce58ef61c59587191039b2ca6",
            strip_prefix = "curl-7.49.1",
            build_file = "@tink_cc_awskms//:third_party/curl.BUILD.bazel",
        )

    if not native.existing_rule("zlib"):
        # Releaes from 2017-01-15; still most recent release on 2019-10-18
        http_archive(
            name = "zlib",
            url = "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
            sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
            strip_prefix = "zlib-1.2.11",
            build_file = "@tink_cc_awskms//:third_party/zlib.BUILD.bazel",
        )
