"""Initialization of dependencies of Tink C++ Cloud KMS."""

# TODO(b/233231652): Revert back to grpc_extra_deps() when it's safe to do so.
#load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")
load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")
load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")
load("@com_envoyproxy_protoc_gen_validate//:dependencies.bzl", "go_third_party")
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@envoy_api//bazel:repositories.bzl", "api_dependencies")
load("@google_cloud_cpp//bazel:google_cloud_cpp_deps.bzl", "google_cloud_cpp_deps")
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@tink_cc//:tink_cc_deps.bzl", "tink_cc_deps")
load("@tink_cc//:tink_cc_deps_init.bzl", "tink_cc_deps_init")
load("@upb//bazel:workspace_deps.bzl", "upb_deps")

def tink_cc_gcpkms_deps_init(
        ignore_version_differences = False,
        register_go = True):
    """Initializes dependencies of Tink C++ GCP Cloud KMS.

    Args:
      ignore_version_differences: Plumbed directly to the invocation of
        apple_rules_dependencies.
      register_go: Whether or not to register Go toolchains. If toolchains
        are already registered, it should not be done again here.
    """

    tink_cc_deps()

    tink_cc_deps_init()

    switched_rules_by_language(
        name = "com_google_googleapis_imports",
        cc = True,
        grpc = True,
    )
    grpc_deps()

    # From this point on, the work normally done by grpc_extra_deps() is
    # locally replicated, to facilitate making makes Go toolchain registration
    # optional. Without this option, Bazel will fail if this is used in a
    # workspace where go_register_toolchains() has already been called.
    #
    # TODO(b/233231652): Upstream this (or an equivalent) fix to gRPC.
    protobuf_deps()

    upb_deps()

    api_dependencies()

    google_cloud_cpp_deps()

    if register_go:
        go_rules_dependencies()
        go_register_toolchains(version = "1.20")

    gazelle_dependencies()

    # Pull-in the go 3rd party dependencies for protoc_gen_validate, which is
    # needed for building C++ xDS protos
    go_third_party()

    apple_rules_dependencies(ignore_version_differences = ignore_version_differences)

    apple_support_dependencies()
