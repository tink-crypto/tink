licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//visibility:public"],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

# tink
TINK_SRCS = [
    "mac.go",
    "aead.go",
    "public_key_sign.go",
    "public_key_verify.go",
    "key_manager.go",
    "keyset_handle.go",
    "cleartext_keyset_handle.go",
    "primitive_set.go",
    "registry.go",
    "keyset_manager.go",
    "crypto_format.go",
]

TINK_TEST_SRCS = [
    "crypto_format_test.go",
    "primitive_set_test.go",
]

TINK_INTERNAL_TEST_SRCS = [
    "keyset_handle_test.go",
]

TINK_DEPS = [
    "//go/util",
    "//go/subtle:random",
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TINK_TEST_DEPS = TINK_DEPS + [
    ":tink",
    "//go/util:testutil",
]

go_library(
    name = "tink",
    srcs = TINK_SRCS,
    deps = TINK_DEPS,
)

go_test(
    name = "tink_test",
    srcs = TINK_TEST_SRCS,
    deps = TINK_TEST_DEPS,
)

# test unexported functions
go_test(
    name = "tink_internal_test",
    srcs = TINK_INTERNAL_TEST_SRCS,
    library = ":tink",
)
