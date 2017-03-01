JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

KEYSET_HANDLE_RESTRICTED_API_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandle, which allows loading cleartext keyset,
    # is restricted.
    "src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandle.java",
]

KEY_MANAGEMENT_RESTRICTED_API_SRCS = [
    # Normal users should not use this API directly, thus this is restricted.
    "src/main/java/com/google/cloud/crypto/tink/KeysetManager.java",
]

# core, without restricted APIs

java_library(
    name = "core",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/*.java",
        ],
        exclude = KEYSET_HANDLE_RESTRICTED_API_SRCS +
                  KEY_MANAGEMENT_RESTRICTED_API_SRCS,
    ),
    javacopts = JAVACOPTS,
    deps = [
        "//proto:java_core",
        "//proto:java_core_compile_imports",
    ],
)

COMMON_JAVA_DEPS = [
    "//java:core",
    "//proto:java_core",
    "//proto:java_core_compile_imports",
]

# public interfaces

java_library(
    name = "public_interfaces",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/Aead.java",
        "src/main/java/com/google/cloud/crypto/tink/Mac.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeySign.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeyVerify.java",
    ],
    javacopts = JAVACOPTS,
)

# aead

java_library(
    name = "aead_subtle",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/subtle/AesGcmJce.java",
        "src/main/java/com/google/cloud/crypto/tink/Random.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java:public_interfaces",
    ],
)

java_library(
    name = "aead",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/aead/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:aead_subtle",
    ],
)

# signature

java_library(
    name = "signature_subtle",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcdsaSignJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcdsaVerifyJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcUtil.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java:public_interfaces",
    ],
)

java_library(
    name = "signature",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/signature/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:signature_subtle",
        "//proto:java_ecdsa",
    ],
)

# mac

java_library(
    name = "mac_subtle",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/subtle/MacJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/Util.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java:public_interfaces",
    ],
)

java_library(
    name = "mac",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/mac/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:mac_subtle",
        "//proto:java_hmac",
        "@com_google_guava_guava//jar",
    ],
)

# public library, everything

java_library(
    name = "tink",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:aead",
        "//java:aead_subtle",
        "//java:core",
        "//java:mac",
        "//java:mac_subtle",
        "//java:signature",
        "//java:signature_subtle",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
        "//proto:java_ecdsa",
        "//proto:java_googlecloudkms",
        "//proto:java_hmac",
    ],
)

# restricted APIs

java_library(
    name = "keyset_handle_restricted",
    srcs = KEYSET_HANDLE_RESTRICTED_API_SRCS,
    javacopts = JAVACOPTS,
    visibility = [
        "//examples/java/envelopeme:__pkg__",
    ],
    deps = COMMON_JAVA_DEPS,
)

java_library(
    name = "key_management_restricted",
    srcs = KEY_MANAGEMENT_RESTRICTED_API_SRCS,
    javacopts = JAVACOPTS,
    visibility = [
        "//examples/java/envelopeme:__pkg__",
    ],
    deps = COMMON_JAVA_DEPS,
)

# tests

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/java/**/*.java",
    ]),
    deps = COMMON_JAVA_DEPS + [
        "//java:key_management_restricted",
        "//java:keyset_handle_restricted",
        "//java:tink",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_fasterxml_jackson_core//jar",
        "@junit_junit_4//jar",
    ],
)

gen_java_test_rules(
    small_tests = glob([
        "src/test/java/**/*ProtoTest.java",
    ]),
    test_files = glob([
        "src/test/java/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
