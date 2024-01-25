"""Initialization of tink-py dependencies."""

load("@rules_python//python:pip.bzl", "pip_install")
load("@pybind11_bazel//:python_configure.bzl", "python_configure")

def tink_py_deps_init(workspace_name):
    pip_install(
        name = "tink_py_pip_deps",
        quiet = False,
        extra_pip_args = ["--no-deps"],
        requirements = "@" + workspace_name + "//:requirements_all.txt",
    )

    # Use `which python3` by default [1] unless PYTHON_BIN_PATH is specified [2].
    #
    # [1] https://github.com/pybind/pybind11_bazel/blob/fc56ce8a8b51e3dd941139d329b63ccfea1d304b/python_configure.bzl#L434
    # [2] https://github.com/pybind/pybind11_bazel/blob/fc56ce8a8b51e3dd941139d329b63ccfea1d304b/python_configure.bzl#L162
    python_configure(name = "local_config_python", python_version = "3")
