JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

KEYSET_HANDLE_RESTRICTED_API_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandleFactory, which allows loading cleartext keyset,
    # is restricted.
    "src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandleFactory.java",
]

# core, without restricted APIs

java_library(
    name = "core",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/*.java",
        ],
        exclude = KEYSET_HANDLE_RESTRICTED_API_SRCS,
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

# public library

java_library(
    name = "tink",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:core",
        "//java:mac",
        "//proto:java_core",
        "//proto:java_hmac",
    ],
)

# restricted API

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
    name = "aead",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/aead/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS,
)

# tests

load(":GenTestRules.bzl", "GenTestRules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/java/**/*.java",
    ]),
    deps = COMMON_JAVA_DEPS + [
        "//java:mac",
        "//java:keyset_handle_restricted",
        "//java:aead",
        "//proto:java_ecdsa",
        "//proto:java_hmac",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_fasterxml_jackson_core//jar",
        "@junit_junit_4//jar",
    ],
)

GenTestRules(
    name = "GeneratedTestRules",
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
