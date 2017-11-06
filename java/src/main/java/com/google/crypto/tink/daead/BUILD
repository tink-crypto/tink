licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "daead_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

FULL_PROTOS = [
    "//proto:aes_siv_java_proto",
    "//proto:common_java_proto",
    "//proto:config_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:aes_siv_java_proto_lite",
    "//proto:common_java_proto_lite",
    "//proto:config_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

java_library(
    name = "daead",
    srcs = [":daead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:daead",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@org_json",
    ] + FULL_PROTOS,
)

java_library(
    name = "android",
    srcs = [":daead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:daead",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@org_json",
    ] + LITE_PROTOS,
)
