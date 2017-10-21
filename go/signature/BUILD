licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "ecdsa_sign_key_manager.go",
    "ecdsa_verify_key_manager.go",
    "public_key_sign_config.go",
    "public_key_sign_factory.go",
    "public_key_verify_config.go",
    "public_key_verify_factory.go",
    "signature_key_templates.go",
]

TEST_SRCS = [
    "ecdsa_sign_key_manager_test.go",
    "ecdsa_verify_key_manager_test.go",
    "public_key_sign_config_test.go",
    "public_key_sign_verify_factory_test.go",
    "public_key_verify_config_test.go",
    "signature_key_templates_test.go",
]

DEPS = [
    "//go/subtle:ecdsa",
    "//go/subtle:random",
    "//go/subtle:subtleutil",
    "//go/tink",
    "//go/util",
    "//proto:common_go_proto",
    "//proto:ecdsa_go_proto",
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TEST_DEPS = DEPS + [
    ":signature",
    "//go/util:testutil",
]

go_library(
    name = "signature",
    srcs = SRCS,
    importpath = "github.com/google/tink/go/signature/signature",
    deps = DEPS,
)

go_test(
    name = "signature_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)
