"""
Dependencies of Python Tink
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def tink_py_deps():
    """ Loads dependencies of Python Tink.
    """

    if not native.existing_rule("rules_python"):
        # Commit from 2019-11-15
        http_archive(
            name = "rules_python",
            strip_prefix = "rules_python-94677401bc56ed5d756f50b441a6a5c7f735a6d4",
            url = "https://github.com/bazelbuild/rules_python/archive/94677401bc56ed5d756f50b441a6a5c7f735a6d4.zip",
            sha256 = "de39bc4d6605e6d395faf5e07516c64c8d833404ee3eb132b5ff1161f9617dec",
        )

    if not native.existing_rule("pybind11"):
        http_archive(
            name = "pybind11",
            build_file = "@pybind11_bazel//:pybind11.BUILD",
            strip_prefix = "pybind11-2.4.3",
            urls = ["https://github.com/pybind/pybind11/archive/v2.4.3.tar.gz"],
        )

    if not native.existing_rule("pybind11_bazel"):
        # Commit from 2019-12-19
        http_archive(
            name = "pybind11_bazel",
            strip_prefix = "pybind11_bazel-d5587e65fb8cbfc0015391a7616dc9c66f64a494",
            url = "https://github.com/pybind/pybind11_bazel/archive/d5587e65fb8cbfc0015391a7616dc9c66f64a494.zip",
            sha256 = "bf8e1f3ebde5ee37ad30c451377b03fbbe42b9d8f24c244aa8af2ccbaeca7e6c",
        )
