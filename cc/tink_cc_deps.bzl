"""Dependencies of C++ Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_cc_deps():
    """Loads dependencies of C++ Tink."""

    # Basic rules we need to add to bazel.
    if not native.existing_rule("bazel_skylib"):
        # Release from 2021-09-27.
        http_archive(
            name = "bazel_skylib",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
                "https://github.com/bazelbuild/bazel-skylib/releases/download/1.1.1/bazel-skylib-1.1.1.tar.gz",
            ],
            sha256 = "c6966ec828da198c5d9adbaa94c05e3a1c7f21bd012a0b29ba8ddbccb2c93b0d",
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
        # Release from 2021-06-08.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.19.3",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip"],
            sha256 = "6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42",
        )

    # -------------------------------------------------------------------------
    # Remote Build Execution (RBE).
    # -------------------------------------------------------------------------
    if not native.existing_rule("bazel_toolchains"):
        # Latest bazel_toolchains package on 2021-10-13.
        http_archive(
            name = "bazel_toolchains",
            sha256 = "179ec02f809e86abf56356d8898c8bd74069f1bd7c56044050c2cd3d79d0e024",
            strip_prefix = "bazel-toolchains-4.1.0",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-toolchains/releases/download/4.1.0/bazel-toolchains-4.1.0.tar.gz",
                "https://github.com/bazelbuild/bazel-toolchains/releases/download/4.1.0/bazel-toolchains-4.1.0.tar.gz",
            ],
        )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    if not native.existing_rule("com_google_absl"):
        # Commit from 2021-12-03.
        http_archive(
            name = "com_google_absl",
            strip_prefix = "abseil-cpp-9336be04a242237cd41a525bedfcf3be1bb55377",
            url = "https://github.com/abseil/abseil-cpp/archive/9336be04a242237cd41a525bedfcf3be1bb55377.zip",
            sha256 = "368be019fc8d69a566ac2cf7a75262d5ba8f6409e3ef3cdbcf0106bdeb32e91c",
        )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    if not native.existing_rule("boringssl"):
        # Commit from 2021-07-02.
        http_archive(
            name = "boringssl",
            strip_prefix = "boringssl-7686eb8ac9bc60198cbc8354fcba7f54c02792ec",
            url = "https://github.com/google/boringssl/archive/7686eb8ac9bc60198cbc8354fcba7f54c02792ec.zip",
            sha256 = "73a7bc71f95f3259ddedc6cb5ba45d02f2359c43e75af354928b0471a428bb84",
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
