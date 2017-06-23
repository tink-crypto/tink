licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

# public interfaces

java_library(
    name = "primitives",
    srcs = [
        "Aead.java",
        "HybridDecrypt.java",
        "HybridEncrypt.java",
        "Mac.java",
        "PublicKeySign.java",
        "PublicKeyVerify.java",
        "StreamingAead.java",
    ],
    javacopts = JAVACOPTS,
)

# restricted APIs

KEYSET_HANDLE_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandle, which allows loading cleartext keyset,
    # is restricted.
    "CleartextKeysetHandle.java",
]

filegroup(
    name = "keyset_handle_srcs",
    srcs = KEYSET_HANDLE_SRCS,
)

# core, without restricted APIs

filegroup(
    name = "tink_srcs",
    srcs = glob(
        [
            "*.java",
        ],
        exclude = KEYSET_HANDLE_SRCS,
    ),
)

java_library(
    name = "tink",
    srcs = [":tink_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//proto:common_java_proto",
        "//proto:tink_java_proto",
        "@com_google_errorprone_error_prone_annotations//jar",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "android",
    srcs = [":tink_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "//proto:common_java_proto_lite",
        "//proto:tink_java_proto_lite",
        "@com_google_errorprone_error_prone_annotations//jar",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "keyset_handle",
    srcs = [
        ":keyset_handle_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":tink",
        "//proto:common_java_proto",
        "//proto:tink_java_proto",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)

java_library(
    name = "keyset_handle_android",
    srcs = [
        ":keyset_handle_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":android",
        "//proto:common_java_proto_lite",
        "//proto:tink_java_proto_lite",
        "@com_google_protobuf_java//:protobuf_java",
    ],
)
