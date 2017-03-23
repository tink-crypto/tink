licenses(["notice"])  # Apache 2.0

# TODO(przydatek): consider adding string_view/string_piece to util
#     instead of relying on stringpiece in protobuf.

# public libraries

# TODO(przydatek): how to export .h-files of factories in this "main" library?
#     (i.e. headers from //cc/aead:aead_factory and //cc/mac:mac_factory)
cc_library(
    name = "cc",
    hdrs = [
        "aead.h",
        "key_manager.h",
        "keyset_handle.h",
        "mac.h",
        "registry.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":aead",
        ":key_manager",
        ":keyset_handle",
        ":mac",
        ":registry",
    ],
)

cc_library(
    name = "aead",
    hdrs = ["aead.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "mac",
    hdrs = ["mac.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "registry",
    srcs = ["registry.h"],
    hdrs = ["registry.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":key_manager",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_tink",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "keyset_handle",
    srcs = ["core/keyset_handle.cc"],
    hdrs = ["keyset_handle.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//proto:cc_tink",
    ],
)

cc_library(
    name = "key_manager",
    srcs = ["key_manager.h"],
    hdrs = ["key_manager.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

# tests

cc_test(
    name = "registry_test",
    size = "small",
    srcs = ["core/registry_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead",
        ":registry",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_aes_ctr_hmac_aead",
        "//proto:cc_aes_gcm",
        "@gtest//:gtest",
    ],
)
