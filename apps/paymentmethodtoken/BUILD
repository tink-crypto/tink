package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "payment_method_token",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java",
        "@com_google_code_findbugs_jsr305//jar",
        "@com_google_http_client//jar",
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
        "@com_google_http_client//jar",
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
