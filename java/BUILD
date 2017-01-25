java_library(
    name = "aead",
    srcs = [
        "src/main/java/com/google/cloud/k2/Aead.java",
    ],
)

# tests

java_test(
    name = "K2ProtoTest",
    size = "small",
    srcs = ["src/test/java/com/google/cloud/k2/K2ProtoTest.java"],
    test_class = "com.google.cloud.k2.K2ProtoTest",
    deps = [
        "//proto:java",
        "@junit_junit_4//jar",
    ],
)
