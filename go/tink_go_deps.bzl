"""
Dependencies of Go Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_go_deps():
    """ Loads dependencies of Go Tink.

    """
    if not native.existing_rule("io_bazel_rules_go"):
        # Release from 2021-01-20
        http_archive(
            name = "io_bazel_rules_go",
            sha256 = "dbf5a9ef855684f84cac2e7ae7886c5a001d4f66ae23f6904da0faaaef0d61fc",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.24.11/rules_go-v0.24.11.tar.gz",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.24.11/rules_go-v0.24.11.tar.gz",
            ],
        )

    if not native.existing_rule("bazel_gazelle"):
        # Release from 2020-09-22
        http_archive(
            name = "bazel_gazelle",
            sha256 = "72d339ff874a382f819aaea80669be049069f502d6c726a07759fdca99653c48",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.22.1/bazel-gazelle-v0.22.1.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.22.1/bazel-gazelle-v0.22.1.tar.gz",
            ],
        )
