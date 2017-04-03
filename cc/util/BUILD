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

cc_library(
    name = "validation",
    srcs = ["validation.h"],
    hdrs = ["validation.h"],
    deps = [
        ":errors",
        ":status",
        "//proto:cc_tink",
    ],
)

cc_library(
    name = "test_util",
    srcs = ["test_util.h"],
    hdrs = ["test_util.h"],
    deps = [
        ":status",
        ":statusor",
        "//cc:aead",
        "//cc:mac",
        "@com_github_google_protobuf//:protobuf_lite",
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
