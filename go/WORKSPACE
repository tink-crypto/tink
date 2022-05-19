workspace(name = "tink_go")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_file(
    name = "google_root_pem",
    executable = 0,
    sha256 = "a9bebf3c3d65d4d421b7e2adbd8600ede614e9e2cc0a05fb2a652f147d7802f3",
    urls = ["https://pki.goog/roots.pem"],
)

# -------------------------------------------------------------------------
# Wycheproof.
# -------------------------------------------------------------------------
# Commit from 2019-12-17
http_archive(
    name = "wycheproof",
    sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
    strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
    url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
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
# Release from 2021-06-08.
http_archive(
    name = "com_google_protobuf",
    sha256 = "6b6bf5cd8d0cca442745c4c3c9f527c83ad6ef35a405f64db5215889ac779b42",
    strip_prefix = "protobuf-3.19.3",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.19.3.zip"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# -------------------------------------------------------------------------
# Remote Build Execution (RBE).
# -------------------------------------------------------------------------
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

load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

rbe_autoconfig(name = "rbe_default")

# -------------------------------------------------------------------------
# Bazel Gazelle.
# -------------------------------------------------------------------------
# Release from 2021-10-11.
http_archive(
    name = "bazel_gazelle",
    sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

# -------------------------------------------------------------------------
# Tink Go Deps.
# -------------------------------------------------------------------------
load("//:deps.bzl", "go_dependencies")

# gazelle:repository_macro deps.bzl%go_dependencies
go_dependencies()

# -------------------------------------------------------------------------
# Bazel rules for Go.
# -------------------------------------------------------------------------
# Release from 2022-03-21
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "f2dcd210c7095febe54b804bb1cd3a58fe8435a909db2ec04e31542631cf715c",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.31.0/rules_go-v0.31.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

# TODO(b/213404399): Remove after Gazelle issue is fixed.
go_repository(
    name = "com_google_cloud_go_compute",
    importpath = "cloud.google.com/go/compute",
    sum = "h1:rSUBvAyVwNJ5uQCKNJFMwPtTvJkfN38b6Pvb9zZoqJ8=",
    version = "v0.1.0",
)

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.17.6",
)

gazelle_dependencies()
