licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

# tink
TINK_SRCS = [
    "mac.go",
    "key_manager.go",
]

TINK_DEPS = [
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

go_library(
    name = "tink",
    srcs = TINK_SRCS,
    deps = TINK_DEPS,
)

go_test(
    name = "tink_test",
    srcs = TINK_SRCS,
    deps = TINK_DEPS,
)
