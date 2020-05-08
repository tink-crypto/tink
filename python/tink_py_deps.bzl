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
        http_archive(
            name = "pybind11",
            build_file = "@pybind11_bazel//:pybind11.BUILD",
            strip_prefix = "pybind11-2.4.3",
            urls = ["https://github.com/pybind/pybind11/archive/v2.4.3.tar.gz"],
        )

    if not native.existing_rule("pybind11_bazel"):
        # Commit from 2020-04-09
        http_archive(
            name = "pybind11_bazel",
            strip_prefix = "pybind11_bazel-34206c29f891dbd5f6f5face7b91664c2ff7185c",
            url = "https://github.com/pybind/pybind11_bazel/archive/34206c29f891dbd5f6f5face7b91664c2ff7185c.zip",
            sha256 = "8d0b776ea5b67891f8585989d54aa34869fc12f14bf33f1dc7459458dd222e95",
        )
