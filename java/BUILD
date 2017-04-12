package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

# public libraries

java_library(
    name = "java",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/aead",
        "//java/src/main/java/com/google/cloud/crypto/tink/aead:aead_envelope",
        "//java/src/main/java/com/google/cloud/crypto/tink/hybrid:hybriddecrypt",
        "//java/src/main/java/com/google/cloud/crypto/tink/hybrid:hybridencrypt",
        "//java/src/main/java/com/google/cloud/crypto/tink/mac",
        "//java/src/main/java/com/google/cloud/crypto/tink/signature",
    ],
)

# restricted

java_library(
    name = "protos",
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_eax",
        "//proto:java_aes_gcm",
        "//proto:java_common",
        "//proto:java_ecdsa",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_gcp_kms",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)

java_library(
    name = "subtle",
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:aead",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:aead_envelope",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:gcp_credential",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybriddecrypt",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybridencrypt",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:mac",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:signature",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:x25519",
    ],
)

java_library(
    name = "keyset_handle_restricted",
    visibility = [
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//java/src/main/java/com/google/cloud/crypto/tink:keyset_handle_restricted",
    ],
)

java_library(
    name = "key_management_restricted",
    visibility = [
        "//tools/tinkey:__pkg__",
    ],
    exports = [
        "//java/src/main/java/com/google/cloud/crypto/tink:key_management_restricted",
    ],
)

# targets for tests

# like :java, but includes protos, restricted APIs and subtle
java_library(
    name = "testonly",
    testonly = 1,
    visibility = [
        "//visibility:public",
    ],
    exports = [
        ":java",
        ":key_management_restricted",
        ":keyset_handle_restricted",
        ":protos",
        ":subtle",
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
        "@com_google_truth//jar",
        "@junit_junit_4//jar",
    ],
)

# Anything in test_files will be a small sized test unless specified in an explicit category.
# Don't hesitate to increase the length when writing legitimately longer tests.
gen_java_test_rules(
    data = [
        "//testdata:credentials",
    ],
    default_test_size = "small",
    medium_tests = [
        "src/test/java/com/google/cloud/crypto/tink/subtle/AesGcmJceTest",
    ],
    test_files = glob([
        "src/test/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
