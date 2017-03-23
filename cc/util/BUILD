licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//cc:__subpackages__"])

cc_library(
    name = "errors",
    srcs = ["errors.cc"],
    hdrs = ["errors.h"],
    deps = [
        ":status",
    ],
)

cc_library(
    name = "status",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
)

cc_library(
    name = "statusor",
    srcs = ["statusor.h"],
    hdrs = ["statusor.h"],
    deps = [
        ":status",
    ],
)

# tests

cc_test(
    name = "errors_test",
    size = "small",
    srcs = ["errors_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-lpthread"],
    deps = [
        ":errors",
        ":status",
        "@gtest//:gtest",
    ],
)
