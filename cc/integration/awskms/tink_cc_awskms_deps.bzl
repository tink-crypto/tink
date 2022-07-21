"""Tink C++ AWS-KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_awskms_deps():
    """Loads dependencies for Tink C++ AWS-KMS."""
    if not native.existing_rule("aws_cpp_sdk"):
        # Release from 2020-06-01
        http_archive(
            name = "aws_cpp_sdk",
            # Must be in sync with defines in third_party/aws_sdk_cpp.BUILD.bazel.
            url = "https://github.com/aws/aws-sdk-cpp/archive/1.7.345.tar.gz",
            sha256 = "7df6491e6e0fac726c00b5e6298d5749b131b25a3dd8b905eb311dc7dcc97aaf",
            strip_prefix = "aws-sdk-cpp-1.7.345",
            build_file = "@tink_cc_awskms//:third_party/aws_sdk_cpp.BUILD.bazel",
        )

    if not native.existing_rule("aws_c_common"):
        http_archive(
            name = "aws_c_common",
            url = "https://github.com/awslabs/aws-c-common/archive/v0.4.29.tar.gz",
            sha256 = "01c2a58553a37b3aa5914d9e0bf7bf14507ff4937bc5872a678892ca20fcae1f",
            strip_prefix = "aws-c-common-0.4.29",
            build_file = "@tink_cc_awskms//:third_party/aws_c_common.BUILD.bazel",
        )

    if not native.existing_rule("aws_c_event_stream"):
        http_archive(
            name = "aws_c_event_stream",
            url = "https://github.com/awslabs/aws-c-event-stream/archive/v0.1.4.tar.gz",
            sha256 = "31d880d1c868d3f3df1e1f4b45e56ac73724a4dc3449d04d47fc0746f6f077b6",
            strip_prefix = "aws-c-event-stream-0.1.4",
            build_file = "@tink_cc_awskms//:third_party/aws_c_event_stream.BUILD.bazel",
        )

    if not native.existing_rule("aws_checksums"):
        http_archive(
            name = "aws_checksums",
            url = "https://github.com/awslabs/aws-checksums/archive/v0.1.5.tar.gz",
            sha256 = "6e6bed6f75cf54006b6bafb01b3b96df19605572131a2260fddaf0e87949ced0",
            strip_prefix = "aws-checksums-0.1.5",
            build_file = "@tink_cc_awskms//:third_party/aws_checksums.BUILD.bazel",
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
        # Releaes from 2022-03-27.
        http_archive(
            name = "zlib",
            url = "https://mirror.bazel.build/zlib.net/zlib-1.2.12.tar.gz",
            sha256 = "91844808532e5ce316b3c010929493c0244f3d37593afd6de04f71821d5136d9",
            strip_prefix = "zlib-1.2.12",
            build_file = "@tink_cc_awskms//:third_party/zlib.BUILD.bazel",
        )
