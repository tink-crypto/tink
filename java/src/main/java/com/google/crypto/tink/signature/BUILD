licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "signature_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

FULL_PROTOS = [
    "//proto:common_java_proto",
    "//proto:config_java_proto",
    "//proto:ecdsa_java_proto",
    "//proto:ed25519_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:common_java_proto_lite",
    "//proto:config_java_proto_lite",
    "//proto:ecdsa_java_proto_lite",
    "//proto:ed25519_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

java_library(
    name = "signature",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
    ] + FULL_PROTOS,
)

java_library(
    name = "android",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
    ] + LITE_PROTOS,
)
