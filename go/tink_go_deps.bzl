"""
Dependencies of Go Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Deprecated.
def tink_go_deps():
    """ Deprecated function that loads dependencies of Go Tink.

    This function should not be used anymore. Instead, these dependencies should be declared directly in the WORKSPACE.
    See: https://github.com/bazelbuild/bazel-gazelle#setup
    """
    if not native.existing_rule("io_bazel_rules_go"):
        # Release from 2022-01-24
        http_archive(
            name = "io_bazel_rules_go",
            sha256 = "d6b2513456fe2229811da7eb67a444be7785f5323c6708b38d851d2b51e54d83",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.30.0/rules_go-v0.30.0.zip",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.30.0/rules_go-v0.30.0.zip",
            ],
        )

    if not native.existing_rule("bazel_gazelle"):
        # Release from 2021-10-11
        http_archive(
            name = "bazel_gazelle",
            sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
            ],
        )

    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )
