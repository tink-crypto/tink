licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "key_util.go",
    "proto_util.go",
]

TEST_SRCS = [
    "key_util_test.go",
]

DEPS = [
    "//proto:tink_go_proto",
    "//proto:hmac_go_proto",
    "//proto:common_go_proto",
    "//proto:aes_gcm_go_proto",
    "//proto:ecdsa_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":util",
    "//go/tink",
    "//go/subtle:random",
]

go_library(
    name = "util",
    srcs = SRCS,
    deps = DEPS,
)

go_test(
    name = "util_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
