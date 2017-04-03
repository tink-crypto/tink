licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//cc:__subpackages__"])

cc_library(
    name = "hmac_openssl",
    srcs = ["hmac_openssl.cc"],
    hdrs = ["hmac_openssl.h"],
    deps = [
        "//cc:mac",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_common",
    ],
)

cc_library(
    name = "random",
    srcs = ["random.cc"],
    hdrs = ["random.h"],
    deps = [
    ],
)

# tests

cc_test(
    name = "hmac_openssl_test",
    size = "small",
    srcs = ["hmac_openssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":hmac_openssl",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_common",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "random_test",
    size = "small",
    srcs = ["random_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-pthread"],
    deps = [
        ":random",
        "@gtest//:gtest",
    ],
)
