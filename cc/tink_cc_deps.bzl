"""Dependencies of Tink C++."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def tink_cc_deps():
    """Loads dependencies of C++ Tink."""

    # Basic rules we need to add to bazel.
    # Release from 2023-11-06.
    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz",
        ],
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
    # Release X.25.1 from 2023-11-15.
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "5c86c077b0794c3e9bb30cac872cf883043febfb0f992137f0a8b1c3d534617c",
        strip_prefix = "protobuf-25.1",
        urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protobuf-25.1.zip"],
    )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    # Release from 2024-01-16.
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "d0f9a580463375978f5ae4e04da39c3664bdaa23724b2f0bf00896a02bf801b9",
        strip_prefix = "abseil-cpp-20240116.0",
        urls = ["https://github.com/abseil/abseil-cpp/archive/refs/tags/20240116.0.zip"],
    )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    # Commit from 2023-09-08.
    maybe(
        http_archive,
        name = "boringssl",
        sha256 = "21b2086e9242b87415767fd6d2d13bd0481e2eb3c336c7ffa24b1f3d7afb09ae",
        strip_prefix = "boringssl-667d54c96acda029523c5bf425e8eb9079dbe94a",
        url = "https://github.com/google/boringssl/archive/667d54c96acda029523c5bf425e8eb9079dbe94a.zip",
    )

    # -------------------------------------------------------------------------
    # Rapidjson.
    # -------------------------------------------------------------------------
    # Release from 2016-08-25 (still the latest release as of 2022-05-05).
    maybe(
        http_archive,
        build_file = "@tink_cc//:third_party/rapidjson.BUILD.bazel",
        name = "rapidjson",
        sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
        strip_prefix = "rapidjson-1.1.0",
        url = "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
    )

def tink_cc_testonly_deps():
    """Test only dependencies for tink-cc."""

    # -------------------------------------------------------------------------
    # Wycheproof.
    # -------------------------------------------------------------------------
    # Commit from 2019-12-17.
    maybe(
        http_archive,
        name = "wycheproof",
        sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
        url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
    )

    # -------------------------------------------------------------------------
    # GoogleTest/GoogleMock.
    # -------------------------------------------------------------------------
    # Release from 2023-08-02.
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4",
        strip_prefix = "googletest-1.14.0",
        url = "https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip",
    )
