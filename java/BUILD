java_library(
    name = "signature",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/PublicKeySign.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeyVerify.java",
    ],
)

java_library(
    name = "aead",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/Aead.java",
    ],
)

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
