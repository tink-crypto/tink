licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("@build_bazel_rules_apple//apple:ios.bzl", "ios_unit_test")

# public libraries

objc_library(
    name = "objc",
    hdrs = [
        "TINKAead.h",
        "TINKKeysetHandle.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":aead",
        ":keyset_handle",
    ],
)

objc_library(
    name = "aead",
    srcs = ["TINKAead.mm"],
    hdrs = [
        "TINKAead.h",
        "TINKAead_Internal.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:aead",
        "//objc/util:errors",
        "//objc/util:strings",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "keyset_handle",
    srcs = ["core/TINKKeysetHandle.mm"],
    hdrs = [
        "TINKKeysetHandle.h",
        "core/TINKKeysetHandle_Internal.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":aead",
        ":keyset_reader",
        "//cc:keyset_handle",
        "//cc/util:status",
        "//objc/util:errors",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "mac",
    hdrs = [
        "TINKMac.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "key_manager",
    hdrs = [
        "TINKKeyManager.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "hybrid_decrypt",
    hdrs = [
        "TINKHybridDecrypt.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "hybrid_encrypt",
    hdrs = [
        "TINKHybridEncrypt.h",
    ],
    visibility = ["//visibility:public"],
)

objc_library(
    name = "keyset_reader",
    srcs = ["core/TINKKeysetReader.mm"],
    hdrs = [
        "TINKKeysetReader.h",
        "core/TINKKeysetReader_Internal.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//cc:keyset_reader",
        "//proto:all_objc_proto",
    ],
)

objc_library(
    name = "binary_keyset_reader",
    srcs = ["core/TINKBinaryKeysetReader.mm"],
    hdrs = [
        "TINKBinaryKeysetReader.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":keyset_reader",
        "//cc:binary_keyset_reader",
        "//objc/util:errors",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "cleartext_keyset_handle",
    srcs = ["core/TINKKeysetHandle+Cleartext.mm"],
    hdrs = [
        "TINKKeysetHandle+Cleartext.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":keyset_handle",
        ":keyset_reader",
        "//cc:cleartext_keyset_handle",
        "//objc/util:errors",
        "//proto:all_objc_proto",
    ],
)

############################
#         Tests            #
############################

ios_unit_test(
    name = "TinkTests",
    minimum_os_version = "9.0",
    deps = [
        ":UnitTestLib",
    ],
)

objc_library(
    name = "UnitTestLib",
    testonly = 1,
    srcs = glob([
        "Tests/UnitTests/**/*.m",
        "Tests/UnitTests/**/*.mm",
    ]),
    hdrs = glob([
        "Tests/UnitTests/**/*.h",
    ]),
    deps = [
        ":aead",
        ":binary_keyset_reader",
        ":cleartext_keyset_handle",
        ":keyset_handle",
        "//cc/util:test_util",
        "//objc/util:strings",
        "//proto:all_objc_proto",
    ],
)
