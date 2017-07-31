licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

FULL_PROTOS = [
    "//proto:common_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:common_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

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

CLEARTEXT_KEYSET_HANDLE_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandle, which allows loading cleartext keyset,
    # is restricted.
    "CleartextKeysetHandle.java",
]

filegroup(
    name = "cleartext_keyset_handle_srcs",
    srcs = CLEARTEXT_KEYSET_HANDLE_SRCS,
)

# core, without restricted APIs

filegroup(
    name = "tink_srcs",
    srcs = glob(
        [
            "*.java",
        ],
        exclude = CLEARTEXT_KEYSET_HANDLE_SRCS,
    ),
)

java_library(
    name = "tink",
    srcs = [":tink_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_google_errorprone_error_prone_annotations//jar",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
    ] + select({
        "//java/build_defs:use_java_proto_full": FULL_PROTOS,
        "//conditions:default": LITE_PROTOS,
    }),
)

java_library(
    name = "cleartext_keyset_handle",
    srcs = [
        ":cleartext_keyset_handle_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":tink",
        "@com_google_protobuf_java//:protobuf_java",
    ] + select({
        "//java/build_defs:use_java_proto_full": FULL_PROTOS,
        "//conditions:default": LITE_PROTOS,
    }),
)
