licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
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
    ],
    javacopts = JAVACOPTS,
    deps = [
        "@com_google_guava//jar",
    ],
)

# restricted APIs

KEYSET_HANDLE_RESTRICTED_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandle, which allows loading cleartext keyset,
    # is restricted.
    "CleartextKeysetHandle.java",
]

filegroup(
    name = "keyset_handle_restricted_srcs",
    srcs = KEYSET_HANDLE_RESTRICTED_SRCS,
)

KEY_MANAGEMENT_RESTRICTED_SRCS = [
    # Normal users should not use this API directly, thus this is restricted.
    "KeysetManager.java",
]

filegroup(
    name = "key_management_restricted_srcs",
    srcs = KEY_MANAGEMENT_RESTRICTED_SRCS,
)

# core, without restricted APIs

filegroup(
    name = "tink_srcs",
    srcs = glob(
        [
            "*.java",
        ],
        exclude = KEYSET_HANDLE_RESTRICTED_SRCS +
                  KEY_MANAGEMENT_RESTRICTED_SRCS,
    ),
)

java_library(
    name = "tink",
    srcs = [":tink_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//proto:java_common",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
        "@com_google_guava//jar",
    ],
)

java_library(
    name = "keyset_handle_restricted",
    srcs = [
        ":keyset_handle_restricted_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":tink",
        "//proto:java_common",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)

java_library(
    name = "key_management_restricted",
    srcs = [
        ":key_management_restricted_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//proto:java_common",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)
