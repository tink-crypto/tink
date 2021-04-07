workspace(name = "tink_base")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

load("@tink_base//:tink_base_deps.bzl", "tink_base_deps")

tink_base_deps()

load("@tink_base//:tink_base_deps_init.bzl", "tink_base_deps_init")

tink_base_deps_init()
