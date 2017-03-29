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
        ":primitive_set",
        ":registry",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:validation",
        "//proto:cc_tink",
        "@com_github_google_protobuf//:protobuf_lite",
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
    name = "crypto_format",
    srcs = ["core/crypto_format.cc"],
    hdrs = ["crypto_format.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc/util:errors",
        "//cc/util:statusor",
        "//proto:cc_tink",
    ],
)

cc_library(
    name = "primitive_set",
    srcs = ["primitive_set.h"],
    hdrs = ["primitive_set.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":crypto_format",
        "//cc/util:errors",
        "//cc/util:statusor",
        "//proto:cc_tink",
    ],
)

cc_library(
    name = "registry",
    srcs = ["registry.h"],
    hdrs = ["registry.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":key_manager",
        ":keyset_handle",
        ":primitive_set",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:validation",
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
        "//proto:cc_tink",
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
        ":crypto_format",
        ":registry",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "//proto:cc_aes_ctr_hmac_aead",
        "//proto:cc_aes_gcm",
        "//proto:cc_tink",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "crypto_format_test",
    size = "small",
    srcs = ["core/crypto_format_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":crypto_format",
        "//proto:cc_tink",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "primitive_set_test",
    size = "small",
    srcs = ["core/primitive_set_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":crypto_format",
        ":mac",
        ":primitive_set",
        "//cc/util:test_util",
        "//proto:cc_tink",
        "@com_github_google_protobuf//:protobuf_lite",
        "@gtest//:gtest",
    ],
)
