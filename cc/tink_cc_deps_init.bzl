"""
Initialization of dependencies of C++ Tink.
"""

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

def tink_cc_deps_init():
    """ Initializes dependencies of C++ Tink.

    """
    switched_rules_by_language(
        name = "com_google_googleapis_imports",
        cc = True,
        grpc = True,
    )
    grpc_deps()
    grpc_extra_deps()
