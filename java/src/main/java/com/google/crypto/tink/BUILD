licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

FULL_PROTOS = [
    "//proto:common_java_proto",
    "//proto:config_java_proto",
    "//proto:tink_java_proto",
]

LITE_PROTOS = [
    "//proto:common_java_proto_lite",
    "//proto:config_java_proto_lite",
    "//proto:tink_java_proto_lite",
]

# public interfaces

java_library(
    name = "primitives",
    srcs = [
        "Aead.java",
        "DeterministicAead.java",
        "HybridDecrypt.java",
        "HybridEncrypt.java",
        "Mac.java",
        "PublicKeySign.java",
        "PublicKeyVerify.java",
        "StreamingAead.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/annotations",
    ],
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
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_google_code_findbugs_jsr305",
        "@com_google_errorprone_error_prone_annotations",
        "@com_google_protobuf//:protobuf_java",
        "@org_json",
    ] + FULL_PROTOS,
)

filegroup(
    name = "android_srcs",
    srcs = glob(
        [
            "*.java",
        ],
        exclude = CLEARTEXT_KEYSET_HANDLE_SRCS + [
            # TextFormat doesn't work with lite protos
            "TextFormatKeysetReaders.java",
            "TextFormatKeysetWriters.java",
        ],
    ),
)

java_library(
    name = "android",
    srcs = [":android_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "//java/src/main/java/com/google/crypto/tink/subtle",
        "@com_google_code_findbugs_jsr305",
        "@com_google_errorprone_error_prone_annotations",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
        "@org_json",
    ] + LITE_PROTOS,
)

java_library(
    name = "cleartext_keyset_handle",
    srcs = [
        ":cleartext_keyset_handle_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":tink",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
    ] + FULL_PROTOS,
)

java_library(
    name = "cleartext_keyset_handle_android",
    srcs = [
        ":cleartext_keyset_handle_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":android",
        "@com_google_protobuf_javalite//:protobuf_java_lite",
    ] + LITE_PROTOS,
)
