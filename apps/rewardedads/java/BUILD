package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "java",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java",
        "@com_google_http_client",
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
        ":java",
        "//java:testonly",
        "@com_google_http_client",
        "@junit",
        "@org_json//jar",
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
