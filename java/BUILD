JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

java_library(
    name = "signature",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/PublicKeySign.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeyVerify.java",
    ],
)

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

java_test(
    name = "TinkProtoTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/crypto/tink/TinkProtoTest.java"],
    test_class = "com.google.cloud.crypto.tink.TinkProtoTest",
    deps = [
        "//proto:java_core",
        "@junit_junit_4//jar",
    ],
)

java_test(
    name = "EcdsaProtoTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/crypto/tink/EcdsaProtoTest.java"],
    test_class = "com.google.cloud.crypto.tink.EcdsaProtoTest",
    deps = [
        "//proto:java_ecdsa",
        "@junit_junit_4//jar",
    ],
)

java_test(
    name = "PrimitiveSetTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/crypto/tink/PrimitiveSetTest.java"],
    test_class = "com.google.cloud.crypto.tink.PrimitiveSetTest",
    deps = COMMON_JAVA_DEPS + [
        "@junit_junit_4//jar",
    ],
)

java_test(
    name = "RegistryTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/crypto/tink/RegistryTest.java"],
    test_class = "com.google.cloud.crypto.tink.RegistryTest",
    deps = COMMON_JAVA_DEPS + [
        "@junit_junit_4//jar",
    ],
)
