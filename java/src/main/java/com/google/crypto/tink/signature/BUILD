licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

filegroup(
    name = "signature_srcs",
    srcs = glob(
        [
            "*.java",
        ],
    ),
)

java_library(
    name = "signature",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature",
        "//proto:common_java_proto",
        "//proto:ecdsa_java_proto",
        "//proto:ed25519_java_proto",
        "//proto:tink_java_proto",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "android",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:android",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//java/src/main/java/com/google/crypto/tink/subtle:signature_android",
        "//proto:common_java_proto_lite",
        "//proto:ecdsa_java_proto_lite",
        "//proto:ed25519_java_proto_lite",
        "//proto:tink_java_proto_lite",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)
