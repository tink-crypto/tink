licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "streamingaead_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

FULL_PROTOS = [
    "//proto:aes_ctr_hmac_streaming_java_proto",
    "//proto:aes_gcm_hkdf_streaming_java_proto",
    "//proto:common_java_proto",
    "//proto:config_java_proto",
    "//proto:hmac_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:aes_ctr_hmac_streaming_java_proto_lite",
    "//proto:aes_gcm_hkdf_streaming_java_proto_lite",
    "//proto:common_java_proto_lite",
    "//proto:config_java_proto_lite",
    "//proto:hmac_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

java_library(
    name = "streamingaead",
    srcs = [":streamingaead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@com_google_code_findbugs_jsr305",
        "@org_json",
    ] + FULL_PROTOS,
)

java_library(
    name = "android",
    srcs = [":streamingaead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@com_google_code_findbugs_jsr305",
        "@org_json",
    ] + LITE_PROTOS,
)
