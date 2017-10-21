licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "aead_config.go",
    "aead_factory.go",
    "aead_key_templates.go",
    "aes_gcm_key_manager.go",
]

TEST_SRCS = [
    "aead_config_test.go",
    "aead_factory_test.go",
    "aead_key_templates_test.go",
    "aes_gcm_key_manager_test.go",
]

DEPS = [
    "//go/subtle:aes",
    "//go/subtle:random",
    "//go/tink",
    "//go/util",
    "//proto:aes_gcm_go_proto",
    "//proto:common_go_proto",
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":aead",
    "//go/util:testutil",
]

go_library(
    name = "aead",
    srcs = SRCS,
    importpath = "github.com/google/tink/go/aead/aead",
    deps = DEPS,
)

go_test(
    name = "aead_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
