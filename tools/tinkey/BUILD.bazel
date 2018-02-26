package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

java_library(
    name = "libtinkey",
    srcs = glob(
        [
            "src/main/**/*.java",
        ],
        exclude = [
            "src/main/java/com/google/crypto/tink/tinkey/Tinkey.java",
        ],
    ),
    javacopts = JAVACOPTS,
    deps = [
        "//java",
        "//java:cleartext_keyset_handle",
        "//java:protos",
        "@args4j//jar",
        "@com_google_guava//jar",
        "@com_google_protobuf//:protobuf_java",
    ],
)

java_binary(
    name = "tinkey",
    srcs = [
        "src/main/java/com/google/crypto/tink/tinkey/Tinkey.java",
    ],
    javacopts = JAVACOPTS,
    main_class = "com.google.crypto.tink.tinkey.Tinkey",
    visibility = ["//tools/testing:__subpackages__"],
    runtime_deps = [
        "@com_fasterxml_jackson_core//jar",
    ],
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
        "//java:test_util",
        "//java:testonly",
        "@com_fasterxml_jackson_core//jar",
        "@com_google_protobuf//:protobuf_java",
        "@com_google_truth//jar",
        "@junit",
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
