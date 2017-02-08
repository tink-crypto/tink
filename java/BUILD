java_library(
    name = "aead",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/Aead.java",
    ],
)

# tests

java_test(
    name = "ProtoTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/crypto/tink/ProtoTest.java"],
    test_class = "com.google.cloud.crypto.tink.ProtoTest",
    deps = [
        "//proto:java",
        "@junit_junit_4//jar",
    ],
)
