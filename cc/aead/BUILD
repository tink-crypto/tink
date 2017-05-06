licenses(["notice"])  # Apache 2.0

cc_library(
    name = "aead_set_wrapper",
    srcs = ["aead_set_wrapper.cc"],
    hdrs = ["aead_set_wrapper.h"],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:aead",
        "//cc:crypto_format",
        "//cc:primitive_set",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "aead_factory",
    srcs = ["aead_factory.cc"],
    hdrs = ["aead_factory.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":aead_set_wrapper",
        ":aes_gcm_key_manager",
        "//cc:aead",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc:primitive_set",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "aes_gcm_key_manager",
    srcs = ["aes_gcm_key_manager.cc"],
    hdrs = ["aes_gcm_key_manager.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:aead",
        "//cc:key_manager",
        "//cc/subtle:aes_gcm_boringssl",
        "//cc/subtle:random",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:validation",
        "//proto:cc_aes_gcm",
        "//proto:cc_common",
        "//proto:cc_tink",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

# tests

cc_test(
    name = "aead_set_wrapper_test",
    size = "small",
    srcs = ["aead_set_wrapper_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead_set_wrapper",
        "//cc:aead",
        "//cc:primitive_set",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:cc_tink",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "aead_factory_test",
    size = "small",
    srcs = ["aead_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead_factory",
        "//cc:aead",
        "//cc:crypto_format",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:cc_aes_gcm",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "aes_gcm_key_manager_test",
    size = "small",
    srcs = ["aes_gcm_key_manager_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aes_gcm_key_manager",
        "//cc:aead",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_aes_eax",
        "//proto:cc_aes_gcm",
        "//proto:cc_common",
        "//proto:cc_tink",
        "@gtest//:gtest",
    ],
)
