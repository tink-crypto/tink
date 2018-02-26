package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "ecies_hkdf_recipient_kem_boringssl",
    srcs = ["ecies_hkdf_recipient_kem_boringssl.cc"],
    hdrs = ["ecies_hkdf_recipient_kem_boringssl.h"],
    deps = [
        ":common_enums",
        ":hkdf",
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:ptr_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "ecies_hkdf_sender_kem_boringssl",
    srcs = ["ecies_hkdf_sender_kem_boringssl.cc"],
    hdrs = ["ecies_hkdf_sender_kem_boringssl.h"],
    deps = [
        ":common_enums",
        ":hkdf",
        ":subtle_util_boringssl",
        "//cc/util:ptr_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "ec_util",
    srcs = ["ec_util.cc"],
    hdrs = ["ec_util.h"],
    deps = [
        ":common_enums",
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "hkdf",
    srcs = ["hkdf.cc"],
    hdrs = ["hkdf.h"],
    deps = [
        ":common_enums",
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "hmac_boringssl",
    srcs = ["hmac_boringssl.cc"],
    hdrs = ["hmac_boringssl.h"],
    deps = [
        ":common_enums",
        ":subtle_util_boringssl",
        "//cc:mac",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "ecdsa_sign_boringssl",
    srcs = ["ecdsa_sign_boringssl.cc"],
    hdrs = ["ecdsa_sign_boringssl.h"],
    deps = [
        ":common_enums",
        ":subtle_util_boringssl",
        "//cc:public_key_sign",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "ecdsa_verify_boringssl",
    srcs = ["ecdsa_verify_boringssl.cc"],
    hdrs = ["ecdsa_verify_boringssl.h"],
    deps = [
        ":common_enums",
        ":subtle_util_boringssl",
        "//cc:public_key_verify",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "aes_gcm_boringssl",
    srcs = ["aes_gcm_boringssl.cc"],
    hdrs = ["aes_gcm_boringssl.h"],
    deps = [
        ":random",
        "//cc:aead",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "encrypt_then_authenticate",
    srcs = [
        "encrypt_then_authenticate.cc",
        "ind_cpa_cipher.h",
    ],
    hdrs = ["encrypt_then_authenticate.h"],
    deps = [
        ":aes_ctr_boringssl",
        ":hmac_boringssl",
        "//cc:aead",
        "//cc:mac",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "aes_ctr_boringssl",
    srcs = [
        "aes_ctr_boringssl.cc",
        "ind_cpa_cipher.h",
    ],
    hdrs = ["aes_ctr_boringssl.h"],
    deps = [
        ":random",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "random",
    srcs = ["random.cc"],
    hdrs = ["random.h"],
    deps = [
        "@boringssl//:crypto",
    ],
)

cc_library(
    name = "common_enums",
    srcs = ["common_enums.cc"],
    hdrs = ["common_enums.h"],
)

cc_library(
    name = "subtle_util_boringssl",
    srcs = ["subtle_util_boringssl.cc"],
    hdrs = ["subtle_util_boringssl.h"],
    deps = [
        ":common_enums",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

# tests
cc_test(
    name = "ecies_hkdf_recipient_kem_boringssl_test",
    size = "small",
    srcs = ["ecies_hkdf_recipient_kem_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":ecies_hkdf_recipient_kem_boringssl",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecies_hkdf_sender_kem_boringssl_test",
    size = "small",
    srcs = ["ecies_hkdf_sender_kem_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":ecies_hkdf_recipient_kem_boringssl",
        ":ecies_hkdf_sender_kem_boringssl",
        ":subtle_util_boringssl",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ec_util_test",
    size = "small",
    srcs = ["ec_util_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ec_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "hkdf_test",
    size = "small",
    srcs = ["hkdf_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":hkdf",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "hmac_boringssl_test",
    size = "small",
    srcs = ["hmac_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":hmac_boringssl",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "aes_gcm_boringssl_test",
    size = "small",
    srcs = ["aes_gcm_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aes_gcm_boringssl",
        "//cc:aead",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "encrypt_then_authenticate_test",
    size = "small",
    srcs = ["encrypt_then_authenticate_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aes_ctr_boringssl",
        ":common_enums",
        ":encrypt_then_authenticate",
        ":hmac_boringssl",
        ":random",
        "//cc:aead",
        "//cc:mac",
        "//cc/util:ptr_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "aes_ctr_boringssl_test",
    size = "small",
    srcs = ["aes_ctr_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aes_ctr_boringssl",
        ":random",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecdsa_sign_boringssl_test",
    size = "small",
    srcs = ["ecdsa_sign_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":ecdsa_sign_boringssl",
        ":ecdsa_verify_boringssl",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecdsa_verify_boringssl_test",
    size = "small",
    srcs = ["ecdsa_verify_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":common_enums",
        ":ecdsa_sign_boringssl",
        ":ecdsa_verify_boringssl",
        "//cc:public_key_sign",
        "//cc:public_key_verify",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "random_test",
    size = "small",
    srcs = ["random_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-pthread"],
    deps = [
        ":random",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "common_enums_test",
    size = "small",
    srcs = ["common_enums_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-pthread"],
    deps = [
        ":common_enums",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "subtle_util_boringssl_test",
    size = "small",
    srcs = ["subtle_util_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-pthread"],
    deps = [
        ":subtle_util_boringssl",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest_main",
    ],
)
