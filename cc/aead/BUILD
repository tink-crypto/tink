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
        "//proto:tink_cc_proto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "aead_config",
    srcs = ["aead_config.cc"],
    hdrs = ["aead_config.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":aes_gcm_key_manager",
        "//cc:key_manager",
        "//cc:registry",
        "//cc/util:status",
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
        "//proto:aes_gcm_cc_proto",
        "//proto:common_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_protobuf//:protobuf_lite",
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
        "//proto:tink_cc_proto",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "aead_config_test",
    size = "small",
    srcs = ["aead_config_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead_config",
        "//cc:registry",
        "//cc/util:status",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "aead_factory_test",
    size = "small",
    srcs = ["aead_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead_config",
        ":aead_factory",
        ":aes_gcm_key_manager",
        "//cc:aead",
        "//cc:crypto_format",
        "//cc:keyset_handle",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:aes_gcm_cc_proto",
        "//proto:tink_cc_proto",
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
        "//proto:aes_eax_cc_proto",
        "//proto:aes_gcm_cc_proto",
        "//proto:common_cc_proto",
        "//proto:tink_cc_proto",
        "@gtest//:gtest",
    ],
)
