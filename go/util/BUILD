licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

SRCS = [
    "keyutil.go",
    "protoutil.go",
]

TEST_SRCS = [
    "keyutil_test.go",
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
    ":testutil",
    "//go/tink",
    "//go/subtle:random",
]

go_library(
    name = "util",
    srcs = SRCS,
    importpath = "github.com/google/tink/go/util/util",
    deps = DEPS,
)

go_test(
    name = "util_test",
    srcs = TEST_SRCS,
    deps = TEST_DEPS,
)

# test util
testutil_SRCS = [
    "testutil/testutil.go",
]

testutil_TEST_SRCS = [
    "testutil/testutil_test.go",
]

testutil_DEPS = [
    ":util",
    "//go/subtle:random",
    "//go/subtle:subtleutil",
    "//go/mac",
    "//go/aead",
    "//go/signature",
    "//go/tink",
    "//proto:tink_go_proto",
    "//proto:hmac_go_proto",
    "//proto:common_go_proto",
    "//proto:aes_gcm_go_proto",
    "//proto:ecdsa_go_proto",
    "@com_github_golang_protobuf//proto:go_default_library",
]

testutil_TEST_DEPS = testutil_DEPS + [
    ":testutil",
]

go_library(
    name = "testutil",
    srcs = testutil_SRCS,
    deps = testutil_DEPS,
)

go_test(
    name = "testutil_test",
    srcs = testutil_TEST_SRCS,
    deps = testutil_TEST_DEPS,
)
