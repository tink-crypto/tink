"""
Initialization of dependencies of Python Tink
"""

load("@rules_python//python:repositories.bzl", "py_repositories")
load("@rules_python//python:pip.bzl", "pip3_import", "pip_repositories")

def tink_py_deps_init(workspace_name):
    py_repositories()
    pip_repositories()
    pip3_import(
        name = "tink_py_pip_deps",
        requirements = "@" + workspace_name + "//:requirements.txt",
    )
