package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

objc_library(
    name = "aead_factory",
    srcs = ["TINKAeadFactory.mm"],
    hdrs = ["TINKAeadFactory.h"],
    deps = [
        "//cc/aead:aead_factory",
        "//cc/util:status",
        "//cc/util:statusor",
        "//objc:aead",
        "//objc:keyset_handle",
        "//objc/util:errors",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "aead_config",
    srcs = ["TINKAeadConfig.mm"],
    hdrs = ["TINKAeadConfig.h"],
    deps = [
        "//cc/aead:aead_config",
    ],
)
