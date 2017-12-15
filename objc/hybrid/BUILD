package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("@build_bazel_rules_apple//apple:ios.bzl", "ios_unit_test")

objc_library(
    name = "hybrid_decrypt_factory",
    srcs = ["TINKHybridDecryptFactory.mm"],
    hdrs = ["TINKHybridDecryptFactory.h"],
    deps = [
        ":hybrid_decrypt_internal",
        ":hybrid_decrypt_key_manager",
        "//cc:hybrid_decrypt",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc/hybrid:hybrid_decrypt_factory",
        "//cc/util:status",
        "//objc:hybrid_decrypt",
        "//objc:key_manager",
        "//objc:keyset_handle",
        "//objc/util:errors",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "hybrid_encrypt_factory",
    srcs = ["TINKHybridEncryptFactory.mm"],
    hdrs = ["TINKHybridEncryptFactory.h"],
    deps = [
        ":hybrid_encrypt_internal",
        ":hybrid_encrypt_key_manager",
        "//cc:hybrid_encrypt",
        "//cc:key_manager",
        "//cc:keyset_handle",
        "//cc/hybrid:hybrid_encrypt_factory",
        "//cc/util:status",
        "//objc:hybrid_encrypt",
        "//objc:key_manager",
        "//objc:keyset_handle",
        "//objc/util:errors",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "hybrid_decrypt_config",
    srcs = ["TINKHybridDecryptConfig.mm"],
    hdrs = ["TINKHybridDecryptConfig.h"],
    deps = [
        ":hybrid_decrypt_key_manager",
        "//cc/hybrid:hybrid_decrypt_config",
        "//objc:key_manager",
        "//objc/util:errors",
    ],
)

objc_library(
    name = "hybrid_encrypt_config",
    srcs = ["TINKHybridEncryptConfig.mm"],
    hdrs = ["TINKHybridEncryptConfig.h"],
    deps = [
        ":hybrid_encrypt_key_manager",
        "//cc/hybrid:hybrid_encrypt_config",
        "//objc:key_manager",
        "//objc/util:errors",
    ],
)

objc_library(
    name = "hybrid_decrypt_key_manager",
    srcs = ["TINKHybridDecryptKeyManager.mm"],
    hdrs = [
        "TINKHybridDecryptKeyManager.h",
        "TINKHybridDecryptKeyManager_Internal.h",
    ],
    deps = [
        "//cc:hybrid_decrypt",
        "//cc:key_manager",
    ],
)

objc_library(
    name = "hybrid_encrypt_key_manager",
    srcs = ["TINKHybridEncryptKeyManager.mm"],
    hdrs = [
        "TINKHybridEncryptKeyManager.h",
        "TINKHybridEncryptKeyManager_Internal.h",
    ],
    deps = [
        "//cc:hybrid_encrypt",
        "//cc:key_manager",
    ],
)

####################################
#              Tests               #
####################################

ios_unit_test(
    name = "HybridTests",
    size = "small",
    minimum_os_version = "9.0",
    deps = [
        ":hybrid_decrypt_config_test",
        ":hybrid_decrypt_factory_test",
        ":hybrid_encrypt_config_test",
        ":hybrid_encrypt_factory_test",
    ],
)

objc_library(
    name = "hybrid_decrypt_factory_test",
    srcs = ["Tests/TINKHybridDecryptFactoryTest.mm"],
    visibility = ["//visibility:private"],
    deps = [
        ":ecies_aead_hkdf_public_key_manager",
        ":hybrid_decrypt_config",
        ":hybrid_decrypt_factory",
        "//cc:crypto_format",
        "//cc/util:status",
        "//cc/util:test_util",
        "//objc:hybrid_decrypt",
        "//objc:hybrid_encrypt",
        "//objc:keyset_handle",
        "//objc/util:strings",
        "//objc/util:test_helpers",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "hybrid_encrypt_factory_test",
    srcs = ["Tests/TINKHybridEncryptFactoryTest.mm"],
    visibility = ["//visibility:private"],
    deps = [
        ":hybrid_encrypt_config",
        ":hybrid_encrypt_factory",
        "//cc/util:status",
        "//cc/util:test_util",
        "//objc:hybrid_encrypt",
        "//objc:keyset_handle",
        "//objc/util:strings",
        "//objc/util:test_helpers",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
        # TODO(candrian): Add CC proto bufs
    ],
)

objc_library(
    name = "hybrid_decrypt_config_test",
    srcs = ["Tests/TINKHybridDecryptConfigTest.m"],
    visibility = ["//visibility:private"],
    deps = [
        ":ecies_aead_hkdf_private_key_manager",
        ":hybrid_decrypt_config",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "hybrid_encrypt_config_test",
    srcs = ["Tests/TINKHybridEncryptConfigTest.m"],
    visibility = ["//visibility:private"],
    deps = [
        ":ecies_aead_hkdf_public_key_manager",
        ":hybrid_encrypt_config",
        "@com_google_absl//absl/strings",
    ],
)

####################################
#         Private/Internal         #
####################################

objc_library(
    name = "ecies_aead_hkdf_private_key_manager",
    srcs = ["TINKEciesAeadHkdfPrivateKeyManager.mm"],
    hdrs = ["TINKEciesAeadHkdfPrivateKeyManager.h"],
    visibility = ["//visibility:private"],
    deps = [
        ":hybrid_decrypt_internal",
        ":hybrid_decrypt_key_manager",
        "//cc:hybrid_decrypt",
        "//cc:key_manager",
        "//cc/hybrid:ecies_aead_hkdf_private_key_manager",
        "//cc/util:status",
        "//objc:key_manager",
        "//objc/util:errors",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:objectivec",
    ],
)

objc_library(
    name = "ecies_aead_hkdf_public_key_manager",
    srcs = ["TINKEciesAeadHkdfPublicKeyManager.mm"],
    hdrs = ["TINKEciesAeadHkdfPublicKeyManager.h"],
    visibility = ["//visibility:private"],
    deps = [
        ":hybrid_encrypt_internal",
        ":hybrid_encrypt_key_manager",
        "//cc:hybrid_encrypt",
        "//cc:key_manager",
        "//cc/hybrid:ecies_aead_hkdf_public_key_manager",
        "//cc/util:status",
        "//objc:key_manager",
        "//objc/util:errors",
        "//objc/util:strings",
        "//proto:all_objc_proto",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:objectivec",
    ],
)

objc_library(
    name = "hybrid_decrypt_internal",
    srcs = [
        "TINKHybridDecryptInternal.mm",
    ],
    hdrs = [
        "TINKHybridDecryptInternal.h",
    ],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:hybrid_decrypt",
        "//objc:hybrid_decrypt",
        "//objc/util:errors",
        "//objc/util:strings",
        "@com_google_absl//absl/strings",
    ],
)

objc_library(
    name = "hybrid_encrypt_internal",
    srcs = [
        "TINKHybridEncryptInternal.mm",
    ],
    hdrs = [
        "TINKHybridEncryptInternal.h",
    ],
    visibility = ["//visibility:private"],
    deps = [
        "//cc:hybrid_encrypt",
        "//objc:hybrid_encrypt",
        "//objc/util:errors",
        "//objc/util:strings",
        "@com_google_absl//absl/strings",
    ],
)
