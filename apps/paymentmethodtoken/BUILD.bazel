package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "paymentmethodtoken",
    srcs = glob([
        "src/main/**/*.java",
    ]),
    javacopts = JAVACOPTS,
    deps = [
        "//java",
        "@com_google_code_findbugs_jsr305//jar",
        "@com_google_http_client//jar",
        "@joda_time//jar",
        "@org_json//jar",
    ],
)

java_binary(
    name = "recipientkeygen",
    srcs = glob([
        "src/main/**/PaymentMethodTokenRecipientKeyGen.java",
    ]),
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenRecipientKeyGen",
    deps = [
        ":paymentmethodtoken",
        "//java",
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
        ":paymentmethodtoken",
        "//java:testonly",
        "@com_google_http_client//jar",
        "@joda_time//jar",
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
