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

# tests

load(":GenTestRules.bzl", "GenTestRules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/java/**/*.java",
    ]),
    deps = COMMON_JAVA_DEPS + [
        "//proto:java_ecdsa",
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
