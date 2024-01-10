"""Tink C++ Cloud KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def _grpc_deps():
    """Imports gRPC and its dependencies.

    Dependencies taken from: https://github.com/grpc/grpc/blob/v1.59.3/bazel/grpc_deps.bzl.
    """
    if "com_google_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_google_protobuf",
            sha256 = "660ce016f987550bc1ccec4a6ee4199afb871799b696227098e3641476a7d566",
            strip_prefix = "protobuf-b2b7a51158418f41cff0520894836c15b1738721",
            urls = [
                # https://github.com/protocolbuffers/protobuf/commits/v24.3
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/protobuf/archive/b2b7a51158418f41cff0520894836c15b1738721.tar.gz",
                "https://github.com/protocolbuffers/protobuf/archive/b2b7a51158418f41cff0520894836c15b1738721.tar.gz",
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
            sha256 = "6fd3496c82919a433219733819a93b56699519a193126959e9c4fedc25e70663",
            strip_prefix = "data-plane-api-e53e7bbd012f81965f2e79848ad9a58ceb67201f",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/envoyproxy/data-plane-api/archive/e53e7bbd012f81965f2e79848ad9a58ceb67201f.tar.gz",
                "https://github.com/envoyproxy/data-plane-api/archive/e53e7bbd012f81965f2e79848ad9a58ceb67201f.tar.gz",
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
            sha256 = "f94e6dddf74739ef5cb30f000e13a2a613f6ebfa5e63588305a71fce8a8a9911",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/rules_apple/releases/download/1.1.3/rules_apple.1.1.3.tar.gz",
                "https://github.com/bazelbuild/rules_apple/releases/download/1.1.3/rules_apple.1.1.3.tar.gz",
            ],
        )

    if "build_bazel_apple_support" not in native.existing_rules():
        http_archive(
            name = "build_bazel_apple_support",
            sha256 = "f4fdf5c9b42b92ea12f229b265d74bb8cedb8208ca7a445b383c9f866cf53392",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/apple_support/releases/download/1.3.1/apple_support.1.3.1.tar.gz",
                "https://github.com/bazelbuild/apple_support/releases/download/1.3.1/apple_support.1.3.1.tar.gz",
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
        # Release from 2023-11-15.
        http_archive(
            name = "com_github_grpc_grpc",
            sha256 = "03ca78ecf847783ac6e895dc7a24834e86981bd8c5408cf86f6ccee886bd3079",
            strip_prefix = "grpc-1.59.3",
            urls = ["https://github.com/grpc/grpc/archive/refs/tags/v1.59.3.zip"],
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

    if not native.existing_rule("com_google_absl"):
        # Release from 2023-09-18.
        http_archive(
            name = "com_google_absl",
            sha256 = "497ebdc3a4885d9209b9bd416e8c3f71e7a1fb8af249f6c2a80b7cbeefcd7e21",
            strip_prefix = "abseil-cpp-20230802.1",
            urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.1.zip"],
        )

    if not native.existing_rule("tink_cc"):
        http_archive(
            name = "tink_cc",
            sha256 = "3080600b6c38421ebaca5bfc460aa965afc88c877695c080019a8905f0f1c1b8",
            strip_prefix = "tink-cc-2.1.1",
            urls = ["https://github.com/tink-crypto/tink-cc/releases/download/v2.1.1/tink-cc-2.1.1.zip"],
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
