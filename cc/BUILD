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
    name = "k2proto_test",
    size = "small",
    srcs = ["k2proto_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        "//proto:cc",
        "@gtest//:gtest",
    ],
)
