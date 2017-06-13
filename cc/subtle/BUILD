package(default_visibility = ["//cc:__subpackages__"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "ecies_hkdf_recipient_kem_boringssl",
    srcs = ["ecies_hkdf_recipient_kem_boringssl.cc"],
    hdrs = ["ecies_hkdf_recipient_kem_boringssl.h"],
    deps = [
        ":hkdf",
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:ptr_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "ecies_hkdf_sender_kem_boringssl",
    srcs = ["ecies_hkdf_sender_kem_boringssl.cc"],
    hdrs = ["ecies_hkdf_sender_kem_boringssl.h"],
    deps = [
        ":hkdf",
        ":subtle_util_boringssl",
        "//cc/util:ptr_util",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "ec_util",
    srcs = ["ec_util.cc"],
    hdrs = ["ec_util.h"],
    deps = [
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "hkdf",
    srcs = ["hkdf.cc"],
    hdrs = ["hkdf.h"],
    deps = [
        ":subtle_util_boringssl",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "hmac_boringssl",
    srcs = ["hmac_boringssl.cc"],
    hdrs = ["hmac_boringssl.h"],
    deps = [
        ":subtle_util_boringssl",
        "//cc:mac",
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
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
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
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
    name = "subtle_util_boringssl",
    srcs = ["subtle_util_boringssl.cc"],
    hdrs = ["subtle_util_boringssl.h"],
    deps = [
        "//cc/util:errors",
        "//cc/util:status",
        "//cc/util:statusor",
        "//proto:common_cc_proto",
        "@boringssl//:crypto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# tests
cc_test(
    name = "ecies_hkdf_recipient_kem_boringssl_test",
    size = "small",
    srcs = ["ecies_hkdf_recipient_kem_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecies_hkdf_recipient_kem_boringssl",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "//proto:common_cc_proto",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "ecies_hkdf_sender_kem_boringssl_test",
    size = "small",
    srcs = ["ecies_hkdf_sender_kem_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":ecies_hkdf_recipient_kem_boringssl",
        ":ecies_hkdf_sender_kem_boringssl",
        ":subtle_util_boringssl",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "//proto:common_cc_proto",
        "@gtest//:gtest",
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
        "//proto:common_cc_proto",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "hkdf_test",
    size = "small",
    srcs = ["hkdf_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":hkdf",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "//proto:common_cc_proto",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "hmac_boringssl_test",
    size = "small",
    srcs = ["hmac_boringssl_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":hmac_boringssl",
        "//cc:mac",
        "//cc/util:status",
        "//cc/util:statusor",
        "//cc/util:test_util",
        "//proto:common_cc_proto",
        "@gtest//:gtest",
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
        "//proto:common_cc_proto",
        "@gtest//:gtest",
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
        "@gtest//:gtest",
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
        "@gtest//:gtest",
    ],
)
