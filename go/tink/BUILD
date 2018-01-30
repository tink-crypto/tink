licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

# tink
PRIMITIVES_SRCS = [
    "aead.go",
    "mac.go",
    "public_key_sign.go",
    "public_key_verify.go",
]

TINK_SRCS = PRIMITIVES_SRCS + [
    "crypto_format.go",
    "cleartext_keyset_handle.go",
    "encrypted_keyset_handle.go",
    "key_manager.go",
    "keyset_handle.go",
    "keyset_manager.go",
    "primitive_set.go",
    "private_key_manager.go",
    "registry.go",
]

TINK_TEST_SRCS = [
    "cleartext_keyset_handle_test.go",
    "crypto_format_test.go",
    "encrypted_keyset_handle_test.go",
    "keyset_manager_test.go",
    "primitive_set_test.go",
    "registry_test.go",
]

TINK_INTERNAL_TEST_SRCS = [
    "keyset_handle_test.go",
]

TINK_DEPS = [
    "//go/util:util",
    "//go/subtle:random",
    "//proto:tink_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

TINK_TEST_DEPS = TINK_DEPS + [
    "//go/aead",
    "//go/mac",
    "//go/signature",
    "//go/subtle:aes",
    "//go/subtle:hmac",
    "//go/util:testutil",
    "//proto:aes_gcm_go_proto",
    "//proto:common_go_proto",
    "//proto:hmac_go_proto",
    ":tink",
]

go_library(
    name = "tink",
    srcs = TINK_SRCS,
    importpath = "github.com/google/tink/go/tink/tink",
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
    importpath = "github.com/google/tink/go/tink/tink_test",
    library = ":tink",
)

# primitives only
go_library(
    name = "primitives",
    srcs = PRIMITIVES_SRCS,
)
