package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "public_key_verify_set_wrapper",
    srcs = ["public_key_verify_set_wrapper.cc"],
    hdrs = ["public_key_verify_set_wrapper.h"],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:crypto_format",
        "//cc:primitive_set",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:tink_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public_key_verify_factory",
    srcs = ["public_key_verify_factory.cc"],
    hdrs = ["public_key_verify_factory.h"],
    deps = [
        ":public_key_verify_set_wrapper",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc:primitive_set",
        "//cc:public_key_verify",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "public_key_sign_set_wrapper",
    srcs = ["public_key_sign_set_wrapper.cc"],
    hdrs = ["public_key_sign_set_wrapper.h"],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:crypto_format",
        "//cc:primitive_set",
        "//cc:public_key_sign",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:tink_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "public_key_sign_factory",
    srcs = ["public_key_sign_factory.cc"],
    hdrs = ["public_key_sign_factory.h"],
    deps = [
        ":public_key_sign_set_wrapper",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc:primitive_set",
        "//cc:public_key_sign",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "ecdsa_sign_key_manager",
    srcs = ["ecdsa_sign_key_manager.cc"],
    hdrs = ["ecdsa_sign_key_manager.h"],
    visibility = ["//objc/hybrid:__pkg__"],
    deps = [
        ":ecdsa_verify_key_manager",
        "//cc:key_manager",
        "//cc:public_key_sign",
        "//cc:registry",
        "//cc/subtle:ecdsa_sign_boringssl",
        "//cc/subtle:subtle_util_boringssl",
        "//cc/util:enums",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
    ],
)

cc_library(
    name = "ecdsa_verify_key_manager",
    srcs = ["ecdsa_verify_key_manager.cc"],
    hdrs = ["ecdsa_verify_key_manager.h"],
    visibility = ["//objc/hybrid:__pkg__"],
    deps = [
        "//cc:key_manager",
        "//cc:public_key_verify",
        "//cc:registry",
        "//cc/subtle:ecdsa_verify_boringssl",
        "//cc/subtle:subtle_util_boringssl",
        "//cc/util:enums",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
    ],
)

cc_library(
    name = "public_key_sign_catalogue",
    srcs = ["public_key_sign_catalogue.cc"],
    hdrs = ["public_key_sign_catalogue.h"],
    deps = [
        ":ecdsa_sign_key_manager",
        "//cc:catalogue",
        "//cc:key_manager",
        "//cc:public_key_sign",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "public_key_verify_catalogue",
    srcs = ["public_key_verify_catalogue.cc"],
    hdrs = ["public_key_verify_catalogue.h"],
    deps = [
        ":ecdsa_verify_key_manager",
        "//cc:catalogue",
        "//cc:key_manager",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:statusor",
    ],
)

cc_library(
    name = "signature_config",
    srcs = ["signature_config.cc"],
    hdrs = ["signature_config.h"],
    deps = [
        ":public_key_sign_catalogue",
        ":public_key_verify_catalogue",
        "//cc:config",
        "//cc:registry",
        "//cc/util:status",
        "//proto:config_cc_proto",
    ],
)

# tests

cc_test(
    name = "public_key_verify_set_wrapper_test",
    size = "small",
    srcs = ["public_key_verify_set_wrapper_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":public_key_verify_set_wrapper",
        "//cc:primitive_set",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "public_key_verify_factory_test",
    size = "small",
    srcs = ["public_key_verify_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecdsa_verify_key_manager",
        ":public_key_verify_factory",
        ":signature_config",
        "//cc:config",
        "//cc:keyset_handle",
        "//cc:public_key_verify",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "public_key_sign_set_wrapper_test",
    size = "small",
    srcs = ["public_key_sign_set_wrapper_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":public_key_sign_set_wrapper",
        "//cc:primitive_set",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "public_key_sign_factory_test",
    size = "small",
    srcs = ["public_key_sign_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecdsa_sign_key_manager",
        ":public_key_sign_factory",
        ":signature_config",
        "//cc:config",
        "//cc:keyset_handle",
        "//cc:public_key_sign",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecdsa_verify_key_manager_test",
    size = "small",
    srcs = ["ecdsa_verify_key_manager_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecdsa_sign_key_manager",
        ":ecdsa_verify_key_manager",
        "//cc:config",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:aes_eax_cc_proto",
        "//proto:common_cc_proto",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecdsa_sign_key_manager_test",
    size = "small",
    srcs = ["ecdsa_sign_key_manager_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecdsa_sign_key_manager",
        "//cc:config",
        "//cc:public_key_sign",
        "//cc:registry",
        "//cc/util:status",
        "//cc/util:test_util",
        "//proto:aes_eax_cc_proto",
        "//proto:common_cc_proto",
        "//proto:ecdsa_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "public_key_sign_catalogue_test",
    size = "small",
    srcs = ["public_key_sign_catalogue_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":public_key_sign_catalogue",
        "//cc:catalogue",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "public_key_verify_catalogue_test",
    size = "small",
    srcs = ["public_key_verify_catalogue_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":public_key_verify_catalogue",
        "//cc:catalogue",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "signature_config_test",
    size = "small",
    srcs = ["signature_config_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":signature_config",
        "//cc:catalogue",
        "//cc:config",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc:registry",
        "//cc/util:status",
        "@com_google_googletest//:gtest_main",
    ],
)
