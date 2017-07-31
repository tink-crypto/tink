licenses(["notice"])  # Apache 2.0

package(
    default_visibility = [
        "//java:__subpackages__",
    ],
)

load("//java/build_defs:javac.bzl", "JAVACOPTS")

FULL_PROTOS = [
    "//proto:common_java_proto",
]

LITE_PROTOS = [
    "//proto:common_java_proto_lite",
]

# common subtle

java_library(
    name = "subtle",
    srcs = [
        "EngineFactory.java",
        "EngineWrapper.java",
        "ImmutableByteArray.java",
        "KmsClient.java",
        "Random.java",
        "SubtleUtil.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "@com_google_errorprone_error_prone_annotations//jar",
    ],
)

# aead subtle

java_library(
    name = "aead",
    srcs = [
        "AesCtrJceCipher.java",
        "AesEaxJce.java",
        "AesGcmJce.java",
        "DjbCipher.java",
        "DjbCipherPoly1305.java",
        "EncryptThenAuthenticate.java",
        "IndCpaCipher.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
    ],
)

# mac subtle

java_library(
    name = "mac",
    srcs = [
        "MacJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
    ],
)

# signature subtle

java_library(
    name = "signature",
    srcs = [
        "Curve25519.java",
        "EcUtil.java",
        "EcdsaSignJce.java",
        "EcdsaVerifyJce.java",
        "Ed25519Sign.java",
        "Ed25519Verify.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":ed25519_internal",
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "@com_google_errorprone_error_prone_annotations//jar",
    ] + select({
        "//java/build_defs:use_java_proto_full": FULL_PROTOS,
        "//conditions:default": LITE_PROTOS,
    }),
)

# hybrid subtle

java_library(
    name = "hybrid",
    srcs = [
        "Curve25519.java",
        "EcUtil.java",
        "EciesAeadHkdfDemHelper.java",
        "EciesAeadHkdfHybridDecrypt.java",
        "EciesAeadHkdfHybridEncrypt.java",
        "EciesHkdfRecipientKem.java",
        "EciesHkdfSenderKem.java",
        "Hkdf.java",
        "NaClCryptoBox.java",
        "ProtoUtil.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":aead",
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "@com_google_errorprone_error_prone_annotations//jar",
    ] + select({
        "//java/build_defs:use_java_proto_full": FULL_PROTOS,
        "//conditions:default": LITE_PROTOS,
    }),
)

# Streaming

java_library(
    name = "streaming",
    srcs = [
        "AesCtrHmacStreaming.java",
        "AesGcmHkdfStreaming.java",
        "Hkdf.java",
        "StreamSegmentDecrypter.java",
        "StreamSegmentEncrypter.java",
        "StreamingAeadDecryptingChannel.java",
        "StreamingAeadEncryptingChannel.java",
        "StreamingAeadSeekableDecryptingChannel.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "@com_google_errorprone_error_prone_annotations//jar",
    ],
)

# x25519 subtle

java_library(
    name = "x25519",
    srcs = [
        "Curve25519.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
    ],
)

# Ed25519 subtle

java_library(
    name = "ed25519_internal",
    srcs = [
        "Ed25519.java",
        "Ed25519Constants.java",
    ],
    javacopts = JAVACOPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":subtle",
        ":x25519",
    ],
)

java_binary(
    name = "Ed25519ConstantsGenerator",
    srcs = [
        "Ed25519ConstantsGenerator.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":x25519",
    ],
)
