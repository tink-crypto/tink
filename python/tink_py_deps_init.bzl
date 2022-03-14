"""
Initialization of dependencies of Python Tink
"""

load("@rules_python//python:pip.bzl", "pip_install")

def tink_py_deps_init(workspace_name):
    pip_install(
        name = "tink_py_pip_deps",
        requirements = "@" + workspace_name + "//:requirements.txt",
    )
