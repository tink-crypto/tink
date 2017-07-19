licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "hmac_key_manager.go",
    "mac_key_templates.go",
]

TEST_SRCS = [
    "hmac_key_manager_test.go",
    "mac_key_templates_test.go",
]

DEPS = [
    "//proto:tink_go_proto",
    "//proto:hmac_go_proto",
    "//proto:common_go_proto",
    "//go/subtle:hmac",
    "//go/subtle:util",
    "//go/subtle:random",
    "//go/tink",
    "@com_github_golang_protobuf//proto:go_default_library",
]

go_library(
    name = "mac",
    srcs = SRCS,
    deps = DEPS,
)

go_test(
    name = "mac_test",
    srcs = TEST_SRCS,
    deps = DEPS + [
        ":mac",
    ],
)
