licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//go:__subpackages__",
    ],
)

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

# hmac subtle
HMAC_SRCS = [
    "hmac.go",
]

HMAC_TEST_SRCS = [
    "hmac_test.go",
]

go_library(
    name = "hmac",
    srcs = HMAC_SRCS,
)

go_test(
    name = "hmac_test",
    srcs = HMAC_SRCS + HMAC_TEST_SRCS,
    deps = [
        "//go:mac_interface",
    ],
)

# random
RANDOM_SRCS = [
    "random.go",
]

RANDOM_TEST_SRCS = [
    "random_test.go",
]

go_library(
    name = "random",
    srcs = RANDOM_SRCS,
)

go_test(
    name = "random_test",
    srcs = RANDOM_SRCS + RANDOM_TEST_SRCS,
)
