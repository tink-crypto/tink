licenses(["notice"])  # Apache 2.0

cc_library(
    name = "aead_factory",
    srcs = ["aead_factory.cc"],
    hdrs = ["aead_factory.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:aead",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc/util:status",
        "//cc/util:statusor",
        "@com_github_google_protobuf//:protobuf_lite",
    ],
)

# tests

cc_test(
    name = "aead_factory_test",
    size = "small",
    srcs = ["aead_factory_test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        ":aead_factory",
        "//cc:aead",
        "//cc/util:status",
        "@gtest//:gtest",
    ],
)
