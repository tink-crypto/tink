licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "hybrid_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

java_library(
    name = "hybrid",
    srcs = [
        ":hybrid_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/aead",
        "//java/src/main/java/com/google/crypto/tink/mac",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:hybrid",
        "//proto:aes_ctr_hmac_aead_java_proto",
        "//proto:aes_ctr_java_proto",
        "//proto:aes_gcm_java_proto",
        "//proto:common_java_proto",
        "//proto:ecies_aead_hkdf_java_proto",
        "//proto:hmac_java_proto",
        "//proto:tink_java_proto",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "android",
    srcs = [
        ":hybrid_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/aead:android",
        "//java/src/main/java/com/google/crypto/tink/mac:android",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:hybrid_android",
        "//proto:aes_ctr_hmac_aead_java_proto_lite",
        "//proto:aes_ctr_java_proto_lite",
        "//proto:aes_gcm_java_proto_lite",
        "//proto:common_java_proto_lite",
        "//proto:ecies_aead_hkdf_java_proto_lite",
        "//proto:hmac_java_proto_lite",
        "//proto:tink_java_proto_lite",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)
