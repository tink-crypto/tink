"""tink-py dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def tink_py_deps():
    """Loads dependencies of tink-py."""
    if not native.existing_rule("google_root_pem"):
        http_file(
            name = "google_root_pem",
            executable = 0,
            urls = ["https://pki.goog/roots.pem"],
            sha256 = "1acf0d4780541758be2c0f998e1e0275232626ed3f8793d8e2fe8e2753750613",
        )

    if not native.existing_rule("rules_python"):
        # Release from 2022-07-15
        http_archive(
            name = "rules_python",
            sha256 = "a3a6e99f497be089f81ec082882e40246bfd435f52f4e82f37e89449b04573f6",
            strip_prefix = "rules_python-0.10.2",
            url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.10.2.tar.gz",
        )

    if not native.existing_rule("pybind11"):
        # Release from 2023-07-17
        http_archive(
            name = "pybind11",
            build_file = "@pybind11_bazel//:pybind11.BUILD",
            strip_prefix = "pybind11-2.11.1",
            urls = ["https://github.com/pybind/pybind11/archive/v2.11.1.tar.gz"],
            sha256 = "d475978da0cdc2d43b73f30910786759d593a9d8ee05b1b6846d1eb16c6d2e0c",
        )

    if not native.existing_rule("pybind11_bazel"):
        # Commit from 2021-01-05
        http_archive(
            name = "pybind11_bazel",
            strip_prefix = "pybind11_bazel-72cbbf1fbc830e487e3012862b7b720001b70672",
            url = "https://github.com/pybind/pybind11_bazel/archive/72cbbf1fbc830e487e3012862b7b720001b70672.zip",
            sha256 = "fec6281e4109115c5157ca720b8fe20c8f655f773172290b03f57353c11869c2",
        )
