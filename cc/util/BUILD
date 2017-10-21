package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "errors",
    srcs = ["errors.cc"],
    hdrs = ["errors.h"],
    deps = [
        ":status",
    ],
)

cc_library(
    name = "strings",
    srcs = ["strings.cc"],
    hdrs = ["strings.h"],
)

cc_library(
    name = "ptr_util",
    srcs = ["ptr_util.h"],
    hdrs = ["ptr_util.h"],
)

cc_library(
    name = "status",
    srcs = ["status.cc"],
    hdrs = ["status.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "statusor",
    srcs = ["statusor.h"],
    hdrs = ["statusor.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":status",
    ],
)

cc_library(
    name = "validation",
    srcs = ["validation.cc"],
    hdrs = ["validation.h"],
    deps = [
        ":errors",
        ":status",
        "//proto:tink_cc_proto",
    ],
)

cc_library(
    name = "test_util",
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    deps = [
        ":status",
        ":statusor",
        "//cc:aead",
        "//cc:binary_keyset_reader",
        "//cc:cleartext_keyset_handle",
        "//cc:hybrid_decrypt",
        "//cc:hybrid_encrypt",
        "//cc:keyset_handle",
        "//cc:mac",
        "//cc/aead:aes_gcm_key_manager",
        "//cc/subtle:subtle_util_boringssl",
        "//proto:aes_gcm_cc_proto",
        "//proto:common_cc_proto",
        "//proto:ecies_aead_hkdf_cc_proto",
        "//proto:tink_cc_proto",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# tests

cc_test(
    name = "errors_test",
    size = "small",
    srcs = ["errors_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-lpthread"],
    deps = [
        ":errors",
        ":status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "strings_test",
    size = "small",
    srcs = ["strings_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    linkopts = ["-lpthread"],
    deps = [
        ":strings",
        "@com_google_googletest//:gtest_main",
    ],
)
