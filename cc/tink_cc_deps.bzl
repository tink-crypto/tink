"""
Dependencies of C++ Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_deps():
    """ Loads dependencies of C++ Tink.

    """

    if not native.existing_rule("com_google_absl"):
        # Commit from 2021-01-13
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-64461421222f8be8663c50e8e82c91c3f95a0d3c",
            url = "https://github.com/abseil/abseil-cpp/archive/64461421222f8be8663c50e8e82c91c3f95a0d3c.zip",
            sha256 = "41d725950d0d3ed4d00020881db84fdc79ac349d9b325ab010686c5a794a822e",
        )

    if not native.existing_rule("boringssl"):
        # Commit from 2020-06-23
        http_archive(
            name = "boringssl",
            strip_prefix = "boringssl-597b810379e126ae05d32c1d94b1a9464385acd0",
            url = "https://github.com/google/boringssl/archive/597b810379e126ae05d32c1d94b1a9464385acd0.zip",
            sha256 = "c4e8414cb36e62d2fee451296cc864f7ad1a4670396c8a67e1ee77ae84cc4167",
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
        # Last commit available at 2020-04-28
        http_archive(
            name = "build_bazel_rules_apple",
            strip_prefix = "rules_apple-3043ed832213cb979b6580d19f95ab8473814fb5",
            url = "https://github.com/bazelbuild/rules_apple/archive/3043ed832213cb979b6580d19f95ab8473814fb5.zip",
            sha256 = "ff18125271214a4e3633241bf3f9a8a0c6b4f4b208f9fee4b360e9fa15538f8a",
        )
    if not native.existing_rule("build_bazel_rules_swift"):
        # Last commit available at 2020-04-28
        http_archive(
            name = "build_bazel_rules_swift",
            strip_prefix = "rules_swift-8767e70f1a8b500f5f3683cb23258964737a3888",
            url = "https://github.com/bazelbuild/rules_swift/archive/8767e70f1a8b500f5f3683cb23258964737a3888.zip",
            sha256 = "cc9d87e67afa75c936eed4725e29ed05ba9a542bc586f943d3333cc6406d6bfc",
        )
    if not native.existing_rule("build_bazel_apple_support"):
        # Last commit available at 2020-04-28
        http_archive(
            name = "build_bazel_apple_support",
            strip_prefix = "apple_support-501b4afb27745c4813a88ffa28acd901408014e4",
            url = "https://github.com/bazelbuild/apple_support/archive/501b4afb27745c4813a88ffa28acd901408014e4.zip",
            sha256 = "8aa07a6388e121763c0164624feac9b20841afa2dd87bac0ba0c3ed1d56feb70",
        )

    # Needed for Cloud KMS API via gRPC.
    if not native.existing_rule("com_google_googleapis"):
        # Commit from 2020-04-09
        http_archive(
            name = "com_google_googleapis",
            url = "https://github.com/googleapis/googleapis/archive/ee4ea76504aa60c2bff9b7c11269c155d8c21e0d.zip",
            sha256 = "687e5b241d365a59d4b95c60d63df07931476c7d14b0c261202ae2aceb44d119",
            strip_prefix = "googleapis-ee4ea76504aa60c2bff9b7c11269c155d8c21e0d",
        )

    if "upb" not in native.existing_rules():
        http_archive(
            name = "upb",
            sha256 = "e9c136e56b98c8eb48ad1c9f8df4a6348e99f9f336ee6199c4259a312c2e3598",
            strip_prefix = "upb-d8f3d6f9d415b31f3ce56d46791706c38fa311bc",
            url = "https://github.com/protocolbuffers/upb/archive/d8f3d6f9d415b31f3ce56d46791706c38fa311bc.tar.gz",
        )

    if "envoy_api" not in native.existing_rules():
        http_archive(
            name = "envoy_api",
            sha256 = "9e8cf42abce32c9b0e9e271b0cb62803084cbe5e5b49f5d5c2aef0766f9d69ca",
            strip_prefix = "data-plane-api-c83ed7ea9eb5fb3b93d1ad52b59750f1958b8bde",
            url = "https://github.com/envoyproxy/data-plane-api/archive/c83ed7ea9eb5fb3b93d1ad52b59750f1958b8bde.tar.gz",
        )

    # gRPC.
    if not native.existing_rule("com_github_grpc_grpc"):
        # Release from 2019-12-05
        # Using the pre-release version due to https://github.com/grpc/grpc/issues/20511
        http_archive(
            name = "com_github_grpc_grpc",
            url = "https://github.com/grpc/grpc/archive/v1.26.0-pre1.tar.gz",
            sha256 = "d6af0859d3ae4693b1955e972aa2e590d6f4d44baaa82651467c6beea453e30e",
            strip_prefix = "grpc-1.26.0-pre1",
        )

    # Not used by Java Tink, but apparently needed for C++ gRPC library.
    if not native.existing_rule("io_grpc_grpc_java"):
        # Commit from 2019-05-02
        http_archive(
            name = "io_grpc_grpc_java",
            strip_prefix = "grpc-java-1.20.0",
            url = "https://github.com/grpc/grpc-java/archive/v1.20.0.tar.gz",
            sha256 = "553d1bdbde3ff4035747c184486bae2f084c75c3c4cdf5ef31a6aa48bdccaf9b",
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
