"""Initialization of dependencies of C++ Tink."""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

def tink_cc_deps_init():
    """Initializes dependencies of C++ Tink."""

    # Initialize Protobuf dependencies.
    protobuf_deps()
