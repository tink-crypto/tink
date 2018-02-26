package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

objc_library(
    name = "mac_factory",
    srcs = ["TINKMacFactory.mm"],
    hdrs = ["TINKMacFactory.h"],
    deps = [
        ":mac_internal",
        ":mac_key_manager",
        "//cc:key_manager",
        "//cc:mac",
        "//cc/mac:mac_factory",
        "//cc/util:status",
        "//objc:key_manager",
        "//objc:keyset_handle",
        "//objc/util:errors",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "mac_config",
    srcs = ["TINKMacConfig.mm"],
    hdrs = ["TINKMacConfig.h"],
    deps = [
        ":mac_key_manager",
        "//cc/mac:mac_config",
        "//objc:key_manager",
    ],
)

objc_library(
    name = "hmac_key_manager",
    srcs = ["TINKHmacKeyManager.mm"],
    hdrs = ["TINKHmacKeyManager.h"],
    deps = [
        ":mac_internal",
        ":mac_key_manager",
        "//cc/mac:hmac_key_manager",
        "//cc/util:status",
        "//objc:key_manager",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:objectivec",
    ],
)

objc_library(
    name = "mac_internal",
    srcs = [
        "TINKMacInternal.mm",
    ],
    hdrs = [
        "TINKMacInternal.h",
    ],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:mac",
        "//objc:mac",
        "//objc/util:errors",
        "//objc/util:strings",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "mac_key_manager",
    hdrs = [
        "TINKMacKeyManager.h",
        "TINKMacKeyManager_Internal.h",
    ],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:key_manager",
        "//cc:mac",
    ],
)
