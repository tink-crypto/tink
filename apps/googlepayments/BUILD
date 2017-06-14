package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

java_library(
    name = "payment_token_method",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    deps = [
        "//java",
        "//java:subtle",
        "@com_google_guava//jar",
        "@json//jar",
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
        ":payment_token_method",
        "//java:testonly",
        "@json//jar",
        "@junit_junit_4//jar",
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
