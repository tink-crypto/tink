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
        # Release X.21.9 from 2022-10-26.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-21.9",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v21.9.zip"],
            sha256 = "5babb8571f1cceafe0c18e13ddb3be556e87e12ceea3463d6b0d0064e6cc1ac3",
        )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    if not native.existing_rule("com_google_absl"):
        # Commit from 2023-01-25.
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-20230125.0",
            url = "https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.zip",
            sha256 = "70a2e30f715a7adcf5b7fcd2fcef7b624204b8e32ede8a23fd35ff5bd7d513b0",
        )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    if not native.existing_rule("boringssl"):
        # Commit from 2022-09-14.
        http_archive(
            name = "boringssl",
            strip_prefix = "boringssl-d345d68d5c4b5471290ebe13f090f1fd5b7e8f58",
            url = "https://github.com/google/boringssl/archive/d345d68d5c4b5471290ebe13f090f1fd5b7e8f58.zip",
            sha256 = "482796f369c8655dbda3be801ae98c47916ecd3bff223d007a723fd5f5ecba22",
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
