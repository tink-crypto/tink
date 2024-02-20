"""Tink C++ Cloud KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def _grpc_deps():
    """Imports gRPC and its dependencies.

    Dependencies taken from: https://github.com/grpc/grpc/blob/v1.59.3/bazel/grpc_deps.bzl.
    """
    if "com_google_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_google_protobuf",
            sha256 = "70f480fe9cb0c6829dbf6be3c388103313aacb65de667b86d981bbc9eaedb905",
            strip_prefix = "protobuf-7f94235e552599141950d7a4a3eaf93bc87d1b22",
            urls = [
                # https://github.com/protocolbuffers/protobuf/commits/v25.0
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/protobuf/archive/7f94235e552599141950d7a4a3eaf93bc87d1b22.tar.gz",
                "https://github.com/protocolbuffers/protobuf/archive/7f94235e552599141950d7a4a3eaf93bc87d1b22.tar.gz",
            ],
            patches = [
                "@com_github_grpc_grpc//third_party:protobuf.patch",
            ],
            patch_args = ["-p1"],
        )

    if "upb" not in native.existing_rules():
        http_archive(
            name = "upb",
            sha256 = "5147e0ab6a28421d1e49004f4a205d84f06b924585e15eaa884cfe13289165b7",
            strip_prefix = "upb-42cd08932e364a4cde35033b73f15c30250d7c2e",
            urls = [
                # https://github.com/protocolbuffers/upb/commits/24.x
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/upb/archive/42cd08932e364a4cde35033b73f15c30250d7c2e.tar.gz",
                "https://github.com/protocolbuffers/upb/archive/42cd08932e364a4cde35033b73f15c30250d7c2e.tar.gz",
            ],
        )

    if "envoy_api" not in native.existing_rules():
        http_archive(
            name = "envoy_api",
            sha256 = "fff067a5d6d776fc88549b5dd4773a6f8f0187b26a859de8b29bd4226a28ee63",
            strip_prefix = "data-plane-api-9d6ffa70677c4dbf23f6ed569676206c4e2edff4",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/envoyproxy/data-plane-api/archive/9d6ffa70677c4dbf23f6ed569676206c4e2edff4.tar.gz",
                "https://github.com/envoyproxy/data-plane-api/archive/9d6ffa70677c4dbf23f6ed569676206c4e2edff4.tar.gz",
            ],
        )

    if "io_bazel_rules_go" not in native.existing_rules():
        http_archive(
            name = "io_bazel_rules_go",
            sha256 = "69de5c704a05ff37862f7e0f5534d4f479418afc21806c887db544a316f3cb6b",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
            ],
        )

    if "build_bazel_rules_apple" not in native.existing_rules():
        http_archive(
            name = "build_bazel_rules_apple",
            sha256 = "34c41bfb59cdaea29ac2df5a2fa79e5add609c71bb303b2ebb10985f93fa20e7",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/rules_apple/releases/download/3.1.1/rules_apple.3.1.1.tar.gz",
                "https://github.com/bazelbuild/rules_apple/releases/download/3.1.1/rules_apple.3.1.1.tar.gz",
            ],
        )

    if "build_bazel_apple_support" not in native.existing_rules():
        http_archive(
            name = "build_bazel_apple_support",
            sha256 = "cf4d63f39c7ba9059f70e995bf5fe1019267d3f77379c2028561a5d7645ef67c",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/apple_support/releases/download/1.11.1/apple_support.1.11.1.tar.gz",
                "https://github.com/bazelbuild/apple_support/releases/download/1.11.1/apple_support.1.11.1.tar.gz",
            ],
        )

    if "bazel_gazelle" not in native.existing_rules():
        http_archive(
            name = "bazel_gazelle",
            sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
            ],
        )

    if "com_envoyproxy_protoc_gen_validate" not in native.existing_rules():
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

    if not native.existing_rule("com_github_grpc_grpc"):
        # Release from 2024-02-12.
        http_archive(
            name = "com_github_grpc_grpc",
            sha256 = "2fc49ec270e03975706db6d440dbb9d4e32b9137c4924365510d0dc4239c6b81",
            strip_prefix = "grpc-1.61.1",
            urls = ["https://github.com/grpc/grpc/archive/refs/tags/v1.61.1.zip"],
        )

def tink_cc_gcpkms_deps():
    """Loads dependencies for Tink C++ Cloud KMS."""

    # Google PKI certs for connecting to GCP KMS.
    if not native.existing_rule("google_root_pem"):
        http_file(
            name = "google_root_pem",
            executable = 0,
            urls = ["https://pki.goog/roots.pem"],
            sha256 = "1acf0d4780541758be2c0f998e1e0275232626ed3f8793d8e2fe8e2753750613",
        )

    _grpc_deps()

    if "com_google_googleapis" not in native.existing_rules():
        http_archive(
            name = "com_google_googleapis",
            sha256 = "b541d28b3fd5c0ce802f02b665cf14dfe7a88bd34d8549215127e7ab1008bbbc",
            strip_prefix = "googleapis-e56f4b1c926f42d6ab127c049158df2dda189914",
            build_file = Label("@com_github_grpc_grpc//bazel:googleapis.BUILD"),
            urls = [
                "https://storage.googleapis.com/cloud-cpp-community-archive/com_google_googleapis/e56f4b1c926f42d6ab127c049158df2dda189914.tar.gz",
                "https://github.com/googleapis/googleapis/archive/e56f4b1c926f42d6ab127c049158df2dda189914.tar.gz",
            ],
        )

    if "google_cloud_cpp" not in native.existing_rules():
        http_archive(
            name = "google_cloud_cpp",
            sha256 = "0f42208ca782249555aac06455b1669c17dfb31d6d8fa4baad29a90f295666bb",
            strip_prefix = "google-cloud-cpp-2.20.0",
            url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.20.0.tar.gz",
        )

    if not native.existing_rule("com_google_absl"):
        # Release from 2024-01-16.
        http_archive(
            name = "com_google_absl",
            sha256 = "d0f9a580463375978f5ae4e04da39c3664bdaa23724b2f0bf00896a02bf801b9",
            strip_prefix = "abseil-cpp-20240116.0",
            urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20240116.0.zip"],
        )

    if not native.existing_rule("tink_cc"):
        http_archive(
            name = "tink_cc",
            sha256 = "3080600b6c38421ebaca5bfc460aa965afc88c877695c080019a8905f0f1c1b8",
            strip_prefix = "tink-cc-2.1.1",
            urls = ["https://github.com/tink-crypto/tink-cc/releases/download/v2.1.1/tink-cc-2.1.1.zip"],
        )

    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
            strip_prefix = "re2-2024-02-01",
            url = "https://github.com/google/re2/releases/download/2024-02-01/re2-2024-02-01.tar.gz",
        )

def tink_cc_gcpkms_testonly_deps():
    """Test only dependencies."""

    if not native.existing_rule("com_google_googletest"):
        # Release from 2023-08-02.
        http_archive(
            name = "com_google_googletest",
            sha256 = "1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4",
            strip_prefix = "googletest-1.14.0",
            url = "https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip",
        )
