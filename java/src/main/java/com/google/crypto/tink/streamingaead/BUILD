licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "streamingaead_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

java_library(
    name = "streamingaead",
    srcs = [":streamingaead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "//proto:aes_ctr_hmac_streaming_java_proto",
        "//proto:aes_gcm_hkdf_streaming_java_proto",
        "//proto:common_java_proto",
        "//proto:tink_java_proto",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "android",
    srcs = [":streamingaead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:streaming",
        "//proto:aes_ctr_hmac_streaming_java_proto_lite",
        "//proto:aes_gcm_hkdf_streaming_java_proto_lite",
        "//proto:common_java_proto_lite",
        "//proto:tink_java_proto_lite",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)
