licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

COMMON_DEPS = [
    "//go/tink:primitives",
    ":random",
    ":subtleutil",
]

# ecdsa subtles
ECDSA_SRCS = [
    "ecdsa/ecdsa.go",
    "ecdsa/ecdsa_sign.go",
    "ecdsa/ecdsa_verify.go",
    "ecdsa/encoding.go",
]

ECDSA_TEST_SRCS = [
    "ecdsa/ecdsa_sign_verify_test.go",
    "ecdsa/ecdsa_test.go",
]

ECDSA_DEPS = COMMON_DEPS

go_library(
    name = "ecdsa",
    srcs = ECDSA_SRCS,
    deps = ECDSA_DEPS,
)

go_test(
    name = "ecdsa_test",
    srcs = ECDSA_TEST_SRCS,
    data = [
        "@wycheproof//testvectors:ecdsa",
    ],
    deps = ECDSA_DEPS + [
        ":ecdsa",
    ],
)

# aes subtles
AES_SRCS = [
    "aes/aes_gcm.go",
]

AES_TEST_SRCS = [
    "aes/aes_gcm_test.go",
]

AES_DEPS = COMMON_DEPS

go_library(
    name = "aes",
    srcs = AES_SRCS,
    deps = AES_DEPS,
)

go_test(
    name = "aes_test",
    srcs = AES_TEST_SRCS,
    data = [
        "@wycheproof//testvectors:aes_gcm",
    ],
    deps = AES_DEPS + [
        ":aes",
    ],
)

# hmac subtle
HMAC_SRCS = [
    "hmac/hmac.go",
]

HMAC_TEST_SRCS = [
    "hmac/hmac_test.go",
]

HMAC_DEPS = COMMON_DEPS

go_library(
    name = "hmac",
    srcs = HMAC_SRCS,
    deps = HMAC_DEPS,
)

go_test(
    name = "hmac_test",
    srcs = HMAC_TEST_SRCS,
    deps = HMAC_DEPS + [
        ":hmac",
    ],
)

# random
RANDOM_SRCS = [
    "random/random.go",
]

RANDOM_TEST_SRCS = [
    "random/random_test.go",
]

go_library(
    name = "random",
    srcs = RANDOM_SRCS,
)

go_test(
    name = "random_test",
    srcs = RANDOM_TEST_SRCS,
    deps = [
        ":random",
    ],
)

# util
UTIL_SRCS = [
    "subtleutil/subtleutil.go",
]

UTIL_TEST_SRCS = [
    "subtleutil/subtleutil_test.go",
]

go_library(
    name = "subtleutil",
    srcs = UTIL_SRCS,
)

go_test(
    name = "subtleutil_test",
    srcs = UTIL_TEST_SRCS,
    deps = [
        ":subtleutil",
    ],
)
