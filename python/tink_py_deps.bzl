"""
Dependencies of Python Tink
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_py_deps():
    """ Loads dependencies of Python Tink.
    """

    if not native.existing_rule("rules_python"):
        # Commit from 2020-03-05
        http_archive(
            name = "rules_python",
            strip_prefix = "rules_python-748aa53d7701e71101dfd15d800e100f6ff8e5d1",
            url = "https://github.com/bazelbuild/rules_python/archive/748aa53d7701e71101dfd15d800e100f6ff8e5d1.zip",
            sha256 = "d3e40ca3b7e00b72d2b1585e0b3396bcce50f0fc692e2b7c91d8b0dc471e3eaf",
        )

    if not native.existing_rule("pybind11"):
        # Commit from 2021-01-05
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
