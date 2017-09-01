package(default_visibility = ["//visibility:private"])

licenses(["notice"])  # Apache 2.0

java_library(
    name = "payment_method_token",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    deps = [
        "//java",
        "//java:subtle",
        "@joda_time//jar",
        "@org_json_json//jar",
    ],
)

# Tests

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/**/*.java",
    ]),
    deps = [
        ":payment_method_token",
        "//java:testonly",
        "@joda_time//jar",
        "@junit_junit_4//jar",
        "@org_json_json//jar",
    ],
)

gen_java_test_rules(
    test_files = glob([
        "src/test/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
