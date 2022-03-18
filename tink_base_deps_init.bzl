"""
Initalization of dependencies of Tink base.
"""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

def tink_base_deps_init():
    """ Initializes dependencies of Tink base.

    """

    # Actual base inits.
    protobuf_deps()

    # Creates a default toolchain config for RBE.
    # Use this as is if you are using the rbe_ubuntu16_04 container,
    # otherwise refer to RBE docs.
    rbe_autoconfig(name = "rbe_default")
