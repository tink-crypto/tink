"""Tink C++ Cloud KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def tink_cc_gcpkms_deps():
    """Loads dependencies for Tink C++ Cloud KMS."""

    # Google PKI certs for connecting to GCP KMS.
    if not native.existing_rule("google_root_pem"):
        http_file(
            name = "google_root_pem",
            executable = 0,
            urls = ["https://pki.goog/roots.pem"],
            sha256 = "9c9b9685ad319b9747c3fe69b46a61c11a0efabdfa09ca6a8b0c3da421036d27",
        )

    # gRPC needs io_bazel_rules_go.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            sha256 = "f2dcd210c7095febe54b804bb1cd3a58fe8435a909db2ec04e31542631cf715c",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
            ],
        )

    # gRPC needs rules_apple, which in turn needs rules_swift and apple_support.
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

    if not native.existing_rule("com_google_googleapis"):
        # Matches version embedded in com_github_grpc_grpc from 2022-05-11.
        http_archive(
            name = "com_google_googleapis",
            sha256 = "5bb6b0253ccf64b53d6c7249625a7e3f6c3bc6402abd52d3778bfa48258703a0",
            strip_prefix = "googleapis-2f9af297c84c55c8b871ba4495e01ade42476c92",
            url = "https://github.com/googleapis/googleapis/archive/2f9af297c84c55c8b871ba4495e01ade42476c92.tar.gz",
        )

    if "upb" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2022-05-11.
        http_archive(
            name = "upb",
            sha256 = "d0fe259d650bf9547e75896a1307bfc7034195e4ae89f5139814d295991ba681",
            strip_prefix = "upb-bef53686ec702607971bd3ea4d4fefd80c6cc6e8",
            url = "https://github.com/protocolbuffers/upb/archive/bef53686ec702607971bd3ea4d4fefd80c6cc6e8.tar.gz",
        )

    if "envoy_api" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2022-05-11.
        http_archive(
            name = "envoy_api",
            sha256 = "c5807010b67033330915ca5a20483e30538ae5e689aa14b3631d6284beca4630",
            strip_prefix = "data-plane-api-9c42588c956220b48eb3099d186487c2f04d32ec",
            url = "https://github.com/envoyproxy/data-plane-api/archive/9c42588c956220b48eb3099d186487c2f04d32ec.tar.gz",
        )

    if "com_envoyproxy_protoc_gen_validate" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2022-05-11.
        http_archive(
            name = "com_envoyproxy_protoc_gen_validate",
            strip_prefix = "protoc-gen-validate-4694024279bdac52b77e22dc87808bd0fd732b69",
            sha256 = "1e490b98005664d149b379a9529a6aa05932b8a11b76b4cd86f3d22d76346f47",
            urls = [
                "https://github.com/envoyproxy/protoc-gen-validate/archive/4694024279bdac52b77e22dc87808bd0fd732b69.tar.gz",
            ],
            patches = ["@com_github_grpc_grpc//third_party:protoc-gen-validate.patch"],
            patch_args = ["-p1"],
        )

    if "bazel_gazelle" not in native.existing_rules():
        # Matches version embedded in com_github_grpc_grpc from 2022-05-11.
        http_archive(
            name = "bazel_gazelle",
            sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
            ],
        )

    if not native.existing_rule("com_github_grpc_grpc"):
        # Release from 2022-05-11.
        http_archive(
            name = "com_github_grpc_grpc",
            sha256 = "94b104231a7794ceb99760dd481d581ede05b96adbc0042d1eb783514d4e2680",
            strip_prefix = "grpc-1.46.1",
            url = "https://github.com/grpc/grpc/archive/v1.46.1.zip",
        )

    # Not used by Java Tink, but apparently needed for C++ gRPC library.
    if not native.existing_rule("io_grpc_grpc_java"):
        # Release from 2022-04-28.
        http_archive(
            name = "io_grpc_grpc_java",
            sha256 = "c1b80883511ceb1e433fb2d4b2f6d85dca0c62a265a6a3e6695144610d6f65b8",
            strip_prefix = "grpc-java-1.46.0",
            url = "https://github.com/grpc/grpc-java/archive/v1.46.0.tar.gz",
        )

    if not native.existing_rule("curl"):
        # Release from 2016-05-30.
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
