package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

# PUBLIC

java_library(
    name = "java",
    visibility = ["//visibility:public"],
    exports = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/aead",
        "//java/src/main/java/com/google/crypto/tink/config",
        "//java/src/main/java/com/google/crypto/tink/hybrid",
        "//java/src/main/java/com/google/crypto/tink/integration/awskms",
        "//java/src/main/java/com/google/crypto/tink/integration/gcpkms",
        "//java/src/main/java/com/google/crypto/tink/mac",
        "//java/src/main/java/com/google/crypto/tink/signature",
        "//java/src/main/java/com/google/crypto/tink/streamingaead",
    ],
)

# like :java, but for Android
android_library(
    name = "android",
    visibility = ["//visibility:public"],
    exports = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/aead:android",
        "//java/src/main/java/com/google/crypto/tink/config:android",
        "//java/src/main/java/com/google/crypto/tink/hybrid:android",
        "//java/src/main/java/com/google/crypto/tink/integration/android",
        "//java/src/main/java/com/google/crypto/tink/mac:android",
        "//java/src/main/java/com/google/crypto/tink/signature:android",
        "//java/src/main/java/com/google/crypto/tink/streamingaead:android",
    ],
)

java_library(
    name = "subtle",
    visibility = ["//visibility:public"],
    exports = [
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:aead",
        "//java/src/main/java/com/google/crypto/tink/subtle:hybrid",
        "//java/src/main/java/com/google/crypto/tink/subtle:mac",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "//java/src/main/java/com/google/crypto/tink/subtle:x25519",
    ],
)

# RESTRICTED

FULL_PROTOS = [
    "//proto:aes_ctr_hmac_aead_java_proto",
    "//proto:aes_ctr_hmac_streaming_java_proto",
    "//proto:aes_ctr_java_proto",
    "//proto:aes_eax_java_proto",
    "//proto:aes_gcm_hkdf_streaming_java_proto",
    "//proto:aes_gcm_java_proto",
    "//proto:chacha20_poly1305_java_proto",
    "//proto:common_java_proto",
    "//proto:config_java_proto",
    "//proto:ecdsa_java_proto",
    "//proto:ecies_aead_hkdf_java_proto",
    "//proto:ed25519_java_proto",
    "//proto:hmac_java_proto",
    "//proto:kms_aead_java_proto",
    "//proto:kms_envelope_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:aes_ctr_hmac_aead_java_proto_lite",
    "//proto:aes_ctr_hmac_streaming_java_proto_lite",
    "//proto:aes_ctr_java_proto_lite",
    "//proto:aes_eax_java_proto_lite",
    "//proto:aes_gcm_hkdf_streaming_java_proto_lite",
    "//proto:aes_gcm_java_proto_lite",
    "//proto:chacha20_poly1305_java_proto_lite",
    "//proto:common_java_proto_lite",
    "//proto:config_java_proto_lite",
    "//proto:ecdsa_java_proto_lite",
    "//proto:ecies_aead_hkdf_java_proto_lite",
    "//proto:ed25519_java_proto_lite",
    "//proto:hmac_java_proto_lite",
    "//proto:kms_aead_java_proto_lite",
    "//proto:kms_envelope_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

java_library(
    name = "protos",
    exports = FULL_PROTOS,
)

java_library(
    name = "protos_android",
    exports = LITE_PROTOS,
)

java_library(
    name = "cleartext_keyset_handle",
    exports = [
        "//java/src/main/java/com/google/crypto/tink:cleartext_keyset_handle",
    ],
)

java_library(
    name = "cleartext_keyset_handle_android",
    exports = [
        "//java/src/main/java/com/google/crypto/tink:cleartext_keyset_handle_android",
    ],
)

# TEST

java_library(
    name = "testonly",
    testonly = 1,
    visibility = [
        "//visibility:public",
    ],
    exports = [
        ":cleartext_keyset_handle",
        ":java",
        ":protos",
    ],
)

android_library(
    name = "testonly_android",
    testonly = 1,
    visibility = ["//visibility:public"],
    exports = [
        ":android",
        ":cleartext_keyset_handle_android",
        ":protos_android",
    ],
)

java_library(
    name = "test_util",
    testonly = 1,
    srcs = glob([
        "src/test/**/TestUtil.java",
    ]),
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":testonly",
        "@com_google_guava//jar",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@com_google_truth//jar",
        "@junit_junit_4//jar",
        "@org_json_json//jar",
    ],
)

# tests

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/**/*.java",
    ]),
    runtime_deps = [
        "@net_bytebuddy//jar",
        "@net_bytebuddy_agent//jar",
        "@org_objenesis//jar",
    ],
    deps = [
        ":testonly",
        "@com_amazonaws_sdk_core//jar",
        "@com_amazonaws_sdk_kms//jar",
        "@com_fasterxml_jackson_core//jar",
        "@com_google_api_client//jar",
        "@com_google_guava//jar",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@com_google_truth//jar",
        "@junit_junit_4//jar",
        "@org_json_json//jar",
        "@org_mockito//jar",
    ],
)

# Anything in test_files will be a small sized test unless specified in an explicit category.
# Don't hesitate to increase the length when writing legitimately longer tests.
gen_java_test_rules(
    data = [
        "//testdata:credentials",
        "//testdata:ecies_keysets",
        "//testdata:wycheproof",
        "@wycheproof//testvectors:aes_gcm",
        "@wycheproof//testvectors:ecdsa",
    ],
    default_test_size = "small",
    large_tests = [
        "src/test/java/com/google/crypto/tink/subtle/AesGcmHkdfStreamingTest",
    ],
    medium_tests = [
        "src/test/java/com/google/crypto/tink/subtle/AesCtrHmacStreamingTest",
        "src/test/java/com/google/crypto/tink/subtle/AesGcmJceTest",
    ],
    test_files = glob([
        "src/test/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
