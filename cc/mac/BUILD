licenses(["notice"])  # Apache 2.0

cc_library(
    name = "mac_factory",
    srcs = ["mac_factory.cc"],
    hdrs = ["mac_factory.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "hmac_key_manager",
    srcs = ["hmac_key_manager.cc"],
    hdrs = ["hmac_key_manager.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:key_manager",
        "//cc:mac",
        "//cc/subtle:hmac_boringssl",
        "//cc/subtle:random",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:validation",
        "//proto:cc_common",
        "//proto:cc_hmac",
        "//proto:cc_tink",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

# tests

cc_test(
    name = "mac_factory_test",
    size = "small",
    srcs = ["mac_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":mac_factory",
        "//cc:mac",
        "//cc/util:status",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "hmac_key_manager_test",
    size = "small",
    srcs = ["hmac_key_manager_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":hmac_key_manager",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:cc_aes_ctr_hmac_aead",
        "//proto:cc_common",
        "//proto:cc_hmac",
        "//proto:cc_tink",
        "@gtest//:gtest",
    ],
)
