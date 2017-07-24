licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

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
    "//proto:tink_go_proto",
    "//proto:hmac_go_proto",
    "//proto:common_go_proto",
    "//go/tink",
    "//go/util",
    "//go/subtle:hmac",
    "//go/subtle:util",
    "//go/subtle:random",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":mac",
    "//go/util:testutil",
]

go_library(
    name = "mac",
    srcs = SRCS,
    deps = DEPS,
)

go_test(
    name = "mac_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
