licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "hmac_key_manager.go",
    "mac_config.go",
    "mac_factory.go",
    "mac_key_templates.go",
]

TEST_SRCS = [
    "hmac_key_manager_test.go",
    "mac_config_test.go",
    "mac_factory_test.go",
    "mac_key_templates_test.go",
]

DEPS = [
    "//go/subtle:hmac",
    "//go/subtle:random",
    "//go/subtle:subtleutil",
    "//go/tink",
    "//go/util",
    "//proto:common_go_proto",
    "//proto:hmac_go_proto",
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":mac",
    "//go/util:testutil",
]

go_library(
    name = "mac",
    srcs = SRCS,
    importpath = "github.com/google/tink/go/mac/mac",
    deps = DEPS,
)

go_test(
    name = "mac_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
