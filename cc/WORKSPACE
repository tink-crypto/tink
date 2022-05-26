workspace(name = "tink_cc")

# Use this repository if you want to build the FIPS module for BoringSSL
# local_repository(
#   name = "boringssl",
#   path = "third_party/boringssl_fips/",
# )

load("@tink_cc//:tink_cc_deps.bzl", "tink_cc_deps")

tink_cc_deps()

load("@tink_cc//:tink_cc_deps_init.bzl", "tink_cc_deps_init")

tink_cc_deps_init()

load("@bazel_toolchains//rules:rbe_repo.bzl", "rbe_autoconfig")

# Creates a default toolchain config for RBE. Use this as is if you are
# using the rbe_ubuntu16_04 container, otherwise refer to RBE docs.
rbe_autoconfig(name = "rbe_default")
