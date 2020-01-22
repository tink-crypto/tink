"""
Initalization of dependencies of Tink base.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

# temporary: loads from other languages
load("//third_party/py:python_configure.bzl", "python_configure")
load("@rules_python//python:repositories.bzl", "py_repositories")
load("@rules_python//python:pip.bzl", "pip3_import", "pip_repositories")
load("@io_bazel_rules_closure//closure:repositories.bzl", "rules_closure_dependencies", "rules_closure_toolchains")
load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies")

def tink_base_deps_init():
    """ Initializes dependencies of Tink base.

    """

    # --------
    # temporary: inits from other languages
    #
    # Python:
    python_configure(name = "local_config_python")
    py_repositories()
    pip_repositories()
    pip3_import(
        name = "tink_py_deps",
        requirements = "//python:requirements.txt",
    )

    # ----- Javascript
    rules_closure_dependencies()
    rules_closure_toolchains()

    # ----- Go
    go_rules_dependencies()

    # --------
    # Actual base inits.
    protobuf_deps()

    # Creates a default toolchain config for RBE.
    # Use this as is if you are using the rbe_ubuntu16_04 container,
    # otherwise refer to RBE docs.
    rbe_autoconfig(name = "rbe_default")
