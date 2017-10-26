licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

# public libraries

objc_library(
    name = "objc",
    hdrs = [
        "TINKAead.h",
        "TINKKeysetHandle.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":aead",
        ":keyset_handle",
    ],
)

objc_library(
    name = "aead",
    srcs = ["TINKAead.mm"],
    hdrs = [
        "TINKAead.h",
        "TINKAead_Internal.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:aead",
        "//objc/util:errors",
        "//objc/util:strings",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "keyset_handle",
    srcs = ["core/TINKKeysetHandle.mm"],
    hdrs = [
        "TINKKeysetHandle.h",
        "core/TINKKeysetHandle_Internal.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:keyset_handle",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "mac",
    hdrs = [
        "TINKMac.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "key_manager",
    hdrs = [
        "TINKKeyManager.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "hybrid_decrypt",
    hdrs = [
        "TINKHybridDecrypt.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "hybrid_encrypt",
    hdrs = [
        "TINKHybridEncrypt.h",
    ],
    visibility = ["//visibility:public"],
)
