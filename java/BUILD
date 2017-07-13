package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

# PUBLIC

java_library(
    name = "java",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/aead",
        "//java/src/main/java/com/google/crypto/tink/hybrid",
        "//java/src/main/java/com/google/crypto/tink/mac",
        "//java/src/main/java/com/google/crypto/tink/signature",
        "//java/src/main/java/com/google/crypto/tink/streamingaead",
    ],
)

# like :java, but for Android
java_library(
    name = "android",
    visibility = ["//visibility:public"],
    exports = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/aead:android",
        "//java/src/main/java/com/google/crypto/tink/hybrid:android",
        "//java/src/main/java/com/google/crypto/tink/mac:android",
        "//java/src/main/java/com/google/crypto/tink/signature:android",
        "//java/src/main/java/com/google/crypto/tink/streamingaead:android",
    ],
)

java_library(
    name = "subtle",
    visibility = ["//visibility:public"],
    exports = [
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:aead",
        "//java/src/main/java/com/google/crypto/tink/subtle:gcp_credential",
        "//java/src/main/java/com/google/crypto/tink/subtle:hybrid",
        "//java/src/main/java/com/google/crypto/tink/subtle:mac",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "//java/src/main/java/com/google/crypto/tink/subtle:x25519",
    ],
)

java_library(
    name = "subtle_android",
    visibility = ["//visibility:public"],
    exports = [
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:aead",
        "//java/src/main/java/com/google/crypto/tink/subtle:gcp_credential",
        "//java/src/main/java/com/google/crypto/tink/subtle:hybrid_android",
        "//java/src/main/java/com/google/crypto/tink/subtle:mac",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature_android",
        "//java/src/main/java/com/google/crypto/tink/subtle:x25519",
    ],
)

# RESTRICTED

java_library(
    name = "protos",
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//proto:aes_ctr_hmac_aead_java_proto",
        "//proto:aes_ctr_hmac_streaming_java_proto",
        "//proto:aes_ctr_java_proto",
        "//proto:aes_eax_java_proto",
        "//proto:aes_gcm_hkdf_streaming_java_proto",
        "//proto:aes_gcm_java_proto",
        "//proto:chacha20_poly1305_java_proto",
        "//proto:common_java_proto",
        "//proto:ecdsa_java_proto",
        "//proto:ecies_aead_hkdf_java_proto",
        "//proto:ed25519_java_proto",
        "//proto:gcp_kms_java_proto",
        "//proto:hmac_java_proto",
        "//proto:kms_envelope_java_proto",
        "//proto:tink_java_proto",
    ],
)

java_library(
    name = "aead_envelope",
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//java/src/main/java/com/google/crypto/tink/aead:envelope",
        "//java/src/main/java/com/google/crypto/tink/subtle:aead_envelope",
    ],
)

java_library(
    name = "keyset_handle",
    visibility = [
        "//tools/testing:__subpackages__",
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//java/src/main/java/com/google/crypto/tink:keyset_handle",
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
        ":aead_envelope",
        ":java",
        ":keyset_handle",
        ":protos",
        ":subtle",
    ],
)

java_library(
    name = "testonly_android",
    testonly = 1,
    visibility = ["//visibility:public"],
    exports = [
        ":android",
        ":subtle_android",
        "//java/src/main/java/com/google/crypto/tink:keyset_handle_android",
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
        "@com_google_protobuf_java//:protobuf_java",
        "@junit_junit_4//jar",
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
    visibility = [
        "//visibility:private",
    ],
    deps = [
        ":testonly",
        "@com_fasterxml_jackson_core//jar",
        "@com_google_api_client//jar",
        "@com_google_guava//jar",
        "@com_google_protobuf_java//:protobuf_java",
        "@com_google_truth//jar",
        "@junit_junit_4//jar",
    ],
)

# Anything in test_files will be a small sized test unless specified in an explicit category.
# Don't hesitate to increase the length when writing legitimately longer tests.
gen_java_test_rules(
    data = [
        "//testdata:credentials",
        "//testdata:ecies_keysets",
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
