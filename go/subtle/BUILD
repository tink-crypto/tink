licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//go:__subpackages__",
    ],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

# ecdsa subtles
ECDSA_SRCS = [
    "ecdsa/ecdsa.go",
    "ecdsa/ecdsa_sign.go",
    "ecdsa/ecdsa_verify.go",
    "ecdsa/encoding.go",
]

ECDSA_TEST_SRCS = [
    "ecdsa/ecdsa_test.go",
    "ecdsa/ecdsa_sign_verify_test.go",
]

ECDSA_DEPS = [
    ":random",
    ":util",
    "//go/tink",
    "//go/util",
    "//proto:common_go_proto",
    "//proto:ecdsa_go_proto",
]

go_library(
    name = "ecdsa",
    srcs = ECDSA_SRCS,
    deps = ECDSA_DEPS,
)

go_test(
    name = "ecdsa_test",
    srcs = ECDSA_TEST_SRCS,
    data = [
        "//testdata:ecdsa",
    ],
    deps = ECDSA_DEPS + [
        ":ecdsa",
        "//go/util:testutil",
    ],
)

# hmac subtle
HMAC_SRCS = [
    "hmac/hmac.go",
]

HMAC_TEST_SRCS = [
    "hmac/hmac_test.go",
]

go_library(
    name = "hmac",
    srcs = HMAC_SRCS,
)

go_test(
    name = "hmac_test",
    srcs = HMAC_TEST_SRCS,
    deps = [
        ":hmac",
        "//go/tink",
    ],
)

# aead subtles
AEAD_SRCS = [
    "aead/aes_gcm.go",
]

AEAD_TEST_SRCS = [
    "aead/aes_gcm_test.go",
]

AEAD_DEPS = [
    ":random",
    ":util",
    "//go/tink",
]

go_library(
    name = "aead",
    srcs = AEAD_SRCS,
    deps = AEAD_DEPS,
)

go_test(
    name = "aead_test",
    srcs = AEAD_TEST_SRCS,
    data = [
        "//testdata:aes_gcm",
    ],
    deps = AEAD_DEPS + [
        ":aead",
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
    "util/util.go",
]

UTIL_TEST_SRCS = [
    "util/util_test.go",
]

UTIL_DEPS = [
    "//proto:common_go_proto",
    "//proto:tink_go_proto",
]

go_library(
    name = "util",
    srcs = UTIL_SRCS,
    deps = UTIL_DEPS,
)

go_test(
    name = "util_test",
    srcs = UTIL_TEST_SRCS,
    deps = UTIL_DEPS + [
        ":util",
    ],
)
