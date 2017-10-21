package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "tink_config",
    srcs = ["tink_config.cc"],
    hdrs = ["tink_config.h"],
    deps = [
        "//cc:config",
        "//cc:key_manager",
        "//cc/hybrid:hybrid_decrypt_config",
        "//cc/hybrid:hybrid_encrypt_config",
        "//cc/util:status",
        "//proto:config_cc_proto",
    ],
)

# tests

cc_test(
    name = "tink_config_test",
    size = "small",
    srcs = ["tink_config_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":tink_config",
        "//cc:aead",
        "//cc:catalogue",
        "//cc:config",
        "//cc:hybrid_decrypt",
        "//cc:hybrid_encrypt",
        "//cc:mac",
        "//cc:registry",
        "//cc/util:status",
        "@com_google_googletest//:gtest_main",
    ],
)
