"""Dependencies of C++ Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_deps():
    """Loads dependencies of C++ Tink."""

    # Basic rules we need to add to bazel.
    if not native.existing_rule("bazel_skylib"):
        # Release from 2022-09-01: https://github.com/bazelbuild/bazel-skylib/releases/tag/1.3.0
        http_archive(
            name = "bazel_skylib",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.3.0/bazel-skylib-1.3.0.tar.gz",
            ],
            sha256 = "74d544d96f4a5bb630d465ca8bbcfe231e3594e5aae57e1edbf17a6eb3ca2506",
        )

    # -------------------------------------------------------------------------
    # Protobuf.
    # -------------------------------------------------------------------------
    # proto_library, cc_proto_library and java_proto_library rules implicitly
    # depend respectively on:
    #   * @com_google_protobuf//:proto
    #   * @com_google_protobuf//:cc_toolchain
    #   * @com_google_protobuf//:java_toolchain
    # This statement defines the @com_google_protobuf repo.
    if not native.existing_rule("com_google_protobuf"):
        # Release X.25.1 from 2023-11-15.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-25.1",
            urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protobuf-25.1.zip"],
            sha256 = "5c86c077b0794c3e9bb30cac872cf883043febfb0f992137f0a8b1c3d534617c",
        )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    if not native.existing_rule("com_google_absl"):
        # Release from 2023-08-02.
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-20230802.0",
            urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20230802.0.zip"],
            sha256 = "2942db09db29359e0c1982986167167d226e23caac50eea1f07b2eb2181169cf",
        )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    if not native.existing_rule("boringssl"):
        # Commit from 2023-02-15.
        http_archive(
            name = "boringssl",
            strip_prefix = "boringssl-5c22014ca513807ed03c657e8ede076164663979",
            url = "https://github.com/google/boringssl/archive/5c22014ca513807ed03c657e8ede076164663979.zip",
            sha256 = "863fc670c456f30923740c1639305132fdfb9d1b25ba385a67ae3862ef12a8af",
        )

    # -------------------------------------------------------------------------
    # GoogleTest/GoogleMock.
    # -------------------------------------------------------------------------
    if not native.existing_rule("com_google_googletest"):
        # Release from 2021-06-11.
        http_archive(
            name = "com_google_googletest",
            strip_prefix = "googletest-release-1.11.0",
            url = "https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz",
            sha256 = "b4870bf121ff7795ba20d20bcdd8627b8e088f2d1dab299a031c1034eddc93d5",
        )

    # -------------------------------------------------------------------------
    # Wycheproof (depends on Rapidjson).
    # -------------------------------------------------------------------------
    if not native.existing_rule("rapidjson"):
        # Release from 2016-08-25 (still the latest release as of 2022-05-05).
        http_archive(
            name = "rapidjson",
            url = "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
            sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
            strip_prefix = "rapidjson-1.1.0",
            build_file = "@tink_cc//:third_party/rapidjson.BUILD.bazel",
        )
    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17.
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )
