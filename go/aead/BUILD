licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "aes_gcm_key_manager.go",
]

TEST_SRCS = [
    "aes_gcm_key_manager_test.go",
]

DEPS = [
    "//proto:tink_go_proto",
    "//proto:common_go_proto",
    "//proto:aes_gcm_go_proto",
    "//go/tink",
    "//go/subtle:aead",
    "//go/subtle:util",
    "//go/subtle:random",
    "//go/util",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":aead",
    "//go/util:testutil",
]

go_library(
    name = "aead",
    srcs = SRCS,
    deps = DEPS,
)

go_test(
    name = "aead_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
