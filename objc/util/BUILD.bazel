package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

objc_library(
    name = "errors",
    srcs = ["TINKErrors.mm"],
    hdrs = ["TINKErrors.h"],
    deps = [
        "//cc/util:status",
    ],
)

objc_library(
    name = "strings",
    srcs = ["TINKStrings.mm"],
    hdrs = ["TINKStrings.h"],
    deps = [
        ":errors",
        "//cc/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:objectivec",
    ],
)

objc_library(
    name = "test_helpers",
    srcs = ["TINKTestHelpers.mm"],
    hdrs = ["TINKTestHelpers.h"],
    deps = [
        ":strings",
        "//cc/subtle:subtle_util_boringssl",
        "//proto:all_objc_proto",
        "@com_google_protobuf//:objectivec",
    ],
)
