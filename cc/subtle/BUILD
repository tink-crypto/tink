package(default_visibility = ["//cc:__subpackages__"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "hmac_boringssl",
    srcs = ["hmac_boringssl.cc"],
    hdrs = ["hmac_boringssl.h"],
    deps = [
        "//cc:mac",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_common",
        "@boringssl//:crypto",
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
    name = "hmac_boringssl_test",
    size = "small",
    srcs = ["hmac_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":hmac_boringssl",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
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
