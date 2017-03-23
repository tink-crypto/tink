licenses(["notice"])  # Apache 2.0

# TODO(przydatek): consider adding string_view/string_piece to util
#     instead of relying on stringpiece in protobuf.
cc_library(
    name = "aead",
    hdrs = ["aead.h"],
    deps = [
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "mac",
    hdrs = ["mac.h"],
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
    deps = [
        ":key_manager",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_core",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "keyset_handle",
    srcs = ["core/keyset_handle.cc"],
    hdrs = ["keyset_handle.h"],
    deps = [
        "//proto:cc_core",
    ],
)

cc_library(
    name = "key_manager",
    srcs = ["key_manager.h"],
    hdrs = ["key_manager.h"],
    deps = [
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "aead_factory",
    srcs = ["core/aead_factory.cc"],
    hdrs = ["aead_factory.h"],
    deps = [
        ":aead",
        ":key_manager",
        ":keyset_handle",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "mac_factory",
    srcs = ["core/mac_factory.cc"],
    hdrs = ["mac_factory.h"],
    deps = [
        ":key_manager",
        ":keyset_handle",
        ":mac",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

# tests

cc_test(
    name = "aead_factory_test",
    size = "small",
    srcs = ["core/aead_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead",
        ":aead_factory",
        "//cc/util:status",
        "//cc/util:statusor",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "mac_factory_test",
    size = "small",
    srcs = ["core/mac_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":mac",
        ":mac_factory",
        "//cc/util:status",
        "//cc/util:statusor",
        "@gtest//:gtest",
    ],
)

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
