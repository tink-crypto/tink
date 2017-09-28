package(default_visibility = ["//visibility:private"])

licenses(["notice"])  # Apache 2.0

java_library(
    name = "webpush",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    deps = [
        "//java",
        "@com_google_code_findbugs_jsr305//jar",
        "@com_google_http_client//jar",
        "@joda_time//jar",
        "@org_json//jar",
    ],
)

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/**/*.java",
    ]),
    deps = [
        ":webpush",
        "//java:testonly",
        "@junit",
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
