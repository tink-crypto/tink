"""
Dependencies of C++ Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_deps():
    """ Loads dependencies of C++ Tink.

    """

    if not native.existing_rule("com_google_absl"):
        # Commit from 2021-12-03
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-9336be04a242237cd41a525bedfcf3be1bb55377",
            url = "https://github.com/abseil/abseil-cpp/archive/9336be04a242237cd41a525bedfcf3be1bb55377.zip",
            sha256 = "368be019fc8d69a566ac2cf7a75262d5ba8f6409e3ef3cdbcf0106bdeb32e91c",
        )

    if not native.existing_rule("boringssl"):
        # Commit from 2021-07-02
        http_archive(
            name = "boringssl",
            strip_prefix = "boringssl-7686eb8ac9bc60198cbc8354fcba7f54c02792ec",
            url = "https://github.com/google/boringssl/archive/7686eb8ac9bc60198cbc8354fcba7f54c02792ec.zip",
            sha256 = "73a7bc71f95f3259ddedc6cb5ba45d02f2359c43e75af354928b0471a428bb84",
        )

    # GoogleTest/GoogleMock framework. Used by most C++ unit-tests.
    if not native.existing_rule("com_google_googletest"):
        # Release from 2019-10-03
        http_archive(
            name = "com_google_googletest",
            strip_prefix = "googletest-1.10.x",
            url = "https://github.com/google/googletest/archive/v1.10.x.zip",
            sha256 = "54a139559cc46a68cf79e55d5c22dc9d48e647a66827342520ce0441402430fe",
        )

    if not native.existing_rule("rapidjson"):
        # Release from 2016-08-25; still the latest release on 2019-10-18
        http_archive(
            name = "rapidjson",
            url = "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
            sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
            strip_prefix = "rapidjson-1.1.0",
            build_file = "@tink_cc//:third_party/rapidjson.BUILD.bazel",
        )

    if not native.existing_rule("aws_cpp_sdk"):
        # Release from 2020-06-01
        http_archive(
            name = "aws_cpp_sdk",
            # Must be in sync with defines in third_party/aws_sdk_cpp.BUILD.bazel.
            url = "https://github.com/aws/aws-sdk-cpp/archive/1.7.345.tar.gz",
            sha256 = "7df6491e6e0fac726c00b5e6298d5749b131b25a3dd8b905eb311dc7dcc97aaf",
            strip_prefix = "aws-sdk-cpp-1.7.345",
            build_file = "@tink_cc//:third_party/aws_sdk_cpp.BUILD.bazel",
        )

    if not native.existing_rule("aws_c_common"):
        http_archive(
            name = "aws_c_common",
            url = "https://github.com/awslabs/aws-c-common/archive/v0.4.29.tar.gz",
            sha256 = "01c2a58553a37b3aa5914d9e0bf7bf14507ff4937bc5872a678892ca20fcae1f",
            strip_prefix = "aws-c-common-0.4.29",
            build_file = "@tink_cc//:third_party/aws_c_common.BUILD.bazel",
        )

    if not native.existing_rule("aws_c_event_stream"):
        http_archive(
            name = "aws_c_event_stream",
            url = "https://github.com/awslabs/aws-c-event-stream/archive/v0.1.4.tar.gz",
            sha256 = "31d880d1c868d3f3df1e1f4b45e56ac73724a4dc3449d04d47fc0746f6f077b6",
            strip_prefix = "aws-c-event-stream-0.1.4",
            build_file = "@tink_cc//:third_party/aws_c_event_stream.BUILD.bazel",
        )

    if not native.existing_rule("aws_checksums"):
        http_archive(
            name = "aws_checksums",
            url = "https://github.com/awslabs/aws-checksums/archive/v0.1.5.tar.gz",
            sha256 = "6e6bed6f75cf54006b6bafb01b3b96df19605572131a2260fddaf0e87949ced0",
            strip_prefix = "aws-checksums-0.1.5",
            build_file = "@tink_cc//:third_party/aws_checksums.BUILD.bazel",
        )

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

    # Needed for Cloud KMS API via gRPC.
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

    # gRPC.
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
            build_file = "@tink_cc//:third_party/curl.BUILD.bazel",
        )

    if not native.existing_rule("zlib"):
        # Releaes from 2017-01-15; still most recent release on 2019-10-18
        http_archive(
            name = "zlib",
            url = "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
            sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
            strip_prefix = "zlib-1.2.11",
            build_file = "@tink_cc//:third_party/zlib.BUILD.bazel",
        )

    # wycheproof, for JSON test vectors
    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )
