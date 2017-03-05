licenses(["notice"])  # Apache 2.0

COMMON_DEPS = [
    # this library provides Status, StatusOr, StringPiece, etc.
    "@com_github_google_protobuf//:protobuf_lite",
]

cc_library(
    name = "aead",
    hdrs = ["public/aead.h"],
    deps = COMMON_DEPS,
)

# tests

cc_test(
    name = "tink_proto_test",
    size = "small",
    srcs = ["tink_proto_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        "//proto:cc_core",
        "@gtest//:gtest",
    ],
)

cc_test(
    name = "ecdsa_proto_test",
    size = "small",
    srcs = ["ecdsa_proto_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        "//proto:cc_ecdsa",
        "@gtest//:gtest",
    ],
)
