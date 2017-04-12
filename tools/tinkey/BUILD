licenses(["notice"])  # Apache 2.0

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

java_library(
    name = "libtinkey",
    srcs = glob(
        [
            "src/main/**/*.java",
        ],
        exclude = [
            "src/main/java/com/google/cloud/crypto/tink/tinkey/Tinkey.java",
        ],
    ),
    javacopts = JAVACOPTS,
    deps = [
        "//java",
        "//java:key_management_restricted",
        "//java:protos",
        "//java:subtle",
        "@args4j//jar",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_code_gson_gson//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
        "@com_google_protobuf_protobuf_java_util//jar",
    ],
)

java_binary(
    name = "tinkey",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/tinkey/Tinkey.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.cloud.crypto.tink.tinkey.Tinkey",
    deps = [
        ":libtinkey",
        "//java",
        "@args4j//jar",
    ],
)

# tests

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/**/*.java",
    ]),
    deps = [
        ":libtinkey",
        "//java",
        "//java:key_management_restricted",
        "//java:keyset_handle_restricted",
        "//java:protos",
        "//java:subtle",
        "//java:test_util",
        "@com_fasterxml_jackson_core//jar",
        "@junit_junit_4//jar",
    ],
)

gen_java_test_rules(
    data = [
        "//testdata:credentials",
    ],
    test_files = glob([
        "src/test/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
