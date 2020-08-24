"""Dependencies of TypeScript/JavaScript Tink."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_javascript_deps():
    """Load dependencies of TypeScript/JavaScript Tink."""
    if not native.existing_rule("build_bazel_rules_nodejs"):
        # Release from 2020-08-18
        http_archive(
            name = "build_bazel_rules_nodejs",
            url = "https://github.com/bazelbuild/rules_nodejs/releases/download/2.0.3/rules_nodejs-2.0.3.tar.gz",
            sha256 = "10fffa29f687aa4d8eb6dfe8731ab5beb63811ab00981fc84a93899641fd4af1",
        )

    if not native.existing_rule("io_bazel_rules_closure"):
        # Commit from 2020-06-26
        http_archive(
            name = "io_bazel_rules_closure",
            strip_prefix = "rules_closure-62746bdd1087c1198a81143e7d8ef3d144a43c0f",
            url = "https://github.com/bazelbuild/rules_closure/archive/62746bdd1087c1198a81143e7d8ef3d144a43c0f.tar.gz",
            sha256 = "9161f3b719008b223846b0df63c7674c6e2d67c81e052a9864f90736505c35f3",
        )

    if not native.existing_rule("bazel_skylib"):
        # Release from 2019-10-09
        http_archive(
            name = "bazel_skylib",
            url = "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.2/bazel-skylib-1.0.2.tar.gz",
            sha256 = "97e70364e9249702246c0e9444bccdc4b847bed1eb03c5a3ece4f83dfe6abc44",
        )
