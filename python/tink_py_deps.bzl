"""
Dependencies of Python Tink
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_py_deps():
    """ Loads dependencies of Python Tink.
    """

    if not native.existing_rule("rules_python"):
        # Release from 2022-01-05
        http_archive(
            name = "rules_python",
            sha256 = "a30abdfc7126d497a7698c29c46ea9901c6392d6ed315171a6df5ce433aa4502",
            strip_prefix = "rules_python-0.6.0",
            url = "https://github.com/bazelbuild/rules_python/archive/0.6.0.tar.gz",
        )

    if not native.existing_rule("pybind11"):
        # Commit from 2021-12-28
        http_archive(
            name = "pybind11",
            build_file = "@pybind11_bazel//:pybind11.BUILD",
            strip_prefix = "pybind11-2.9.0",
            urls = ["https://github.com/pybind/pybind11/archive/v2.9.0.tar.gz"],
            sha256 = "057fb68dafd972bc13afb855f3b0d8cf0fa1a78ef053e815d9af79be7ff567cb",
        )

    if not native.existing_rule("pybind11_bazel"):
        # Commit from 2021-01-05
        http_archive(
            name = "pybind11_bazel",
            strip_prefix = "pybind11_bazel-72cbbf1fbc830e487e3012862b7b720001b70672",
            url = "https://github.com/pybind/pybind11_bazel/archive/72cbbf1fbc830e487e3012862b7b720001b70672.zip",
            sha256 = "fec6281e4109115c5157ca720b8fe20c8f655f773172290b03f57353c11869c2",
        )
