"""
Initialization of dependencies of Go Tink.
"""

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
load("@com_github_google_tink_go//:deps.bzl", "go_dependencies")

# Deprecated.
def tink_go_deps_init():
    """ Deprecated function to initializes dependencies of Go Tink.

    This should not be used anymore. Instead, each workspace should generate
    its own go_dependencies() using gazelle. And go_rules_dependencies(),
    go_register_toolchains() and gazelle_dependencies() should be called in the WORKSPACE.
    """
    go_rules_dependencies()
    go_register_toolchains()
    gazelle_dependencies()
    go_dependencies()
