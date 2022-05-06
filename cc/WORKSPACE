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

