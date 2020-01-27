"""
Dependencies of Go Tink.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_go_deps():
    """ Loads dependencies of Go Tink.

    """
    if not native.existing_rule("io_bazel_rules_go"):
        # Release from 2019-10-14
        http_archive(
            name = "io_bazel_rules_go",
            urls = [
                "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/v0.20.2/rules_go-v0.20.2.tar.gz",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.20.2/rules_go-v0.20.2.tar.gz",
            ],
            sha256 = "b9aa86ec08a292b97ec4591cf578e020b35f98e12173bbd4a921f84f583aebd9",
        )

    if not native.existing_rule("bazel_gazelle"):
        # Release from 2019-10-14
        http_archive(
            name = "bazel_gazelle",
            urls = [
                "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.1/bazel-gazelle-v0.19.1.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.1/bazel-gazelle-v0.19.1.tar.gz",
            ],
            sha256 = "86c6d481b3f7aedc1d60c1c211c6f76da282ae197c3b3160f54bd3a8f847896f",
        )

    if not native.existing_rule("wycheproof"):
        # Commit from 2019-12-17
        http_archive(
            name = "wycheproof",
            strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
            url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
            sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        )
