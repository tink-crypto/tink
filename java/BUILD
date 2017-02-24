JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

# core

java_library(
    name = "core",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/*.java",
    ]),
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

# mac

java_library(
    name = "mac_subtle",
    srcs = glob([
        "src/main/java/com/google/cloud/crypto/tink/subtle/MacJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/Util.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java:core",
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
