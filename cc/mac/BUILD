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
        "//cc/util:statusor",
        "@gtest//:gtest",
    ],
)
