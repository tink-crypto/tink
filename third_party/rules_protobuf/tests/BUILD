package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//third_party/rules_protobuf/javalite:rules.bzl", "java_lite_proto_library")

java_lite_proto_library(
    name = "message_java_lite_proto",
    protos = ["message.proto"],
    verbose = 0,
)

java_test(
    name = "javalite_test",
    srcs = [
        "src/test/java/JavaLiteTest.java",
    ],
    test_class = "JavaLiteTest",
    deps = [
        ":message_java_lite_proto",
        "@com_google_protobuf_java//:protobuf_java",
        "@junit_junit_4//jar",
    ],
)
