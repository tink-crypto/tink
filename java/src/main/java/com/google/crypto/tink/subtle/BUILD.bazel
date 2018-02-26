licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//tools/build_defs:internal_pkg"])

load("//tools/build_defs:javac.bzl", "JAVACOPTS")

# common subtle

java_library(
    name = "subtle",
    srcs = [
        "Base64.java",
        "Bytes.java",
        "EllipticCurves.java",
        "EngineFactory.java",
        "EngineWrapper.java",
        "Hex.java",
        "ImmutableByteArray.java",
        "Random.java",
        "SubtleUtil.java",
        "Validators.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "@com_google_errorprone_error_prone_annotations",
    ],
)

# aead subtle

java_library(
    name = "aead",
    srcs = [
        "AesCtrJceCipher.java",
        "AesEaxJce.java",
        "AesGcmJce.java",
        "ChaCha20.java",
        "ChaCha20Base.java",
        "ChaCha20Poly1305.java",
        "EncryptThenAuthenticate.java",
        "IndCpaCipher.java",
        "Poly1305.java",
        "Snuffle.java",
        "SnufflePoly1305.java",
        "XChaCha20.java",
        "XChaCha20Poly1305.java",
        "XSalsa20.java",
        "XSalsa20Poly1305.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
    ],
)

# deterministic aead subtle

java_library(
    name = "daead",
    srcs = [
        "AesSiv.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":mac",
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
    ],
)

# mac subtle

java_library(
    name = "mac",
    srcs = [
        "AesCmac.java",
        "AesUtil.java",
        "MacJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
    ],
)

# signature subtle

java_library(
    name = "signature",
    srcs = [
        "EcdsaSignJce.java",
        "EcdsaVerifyJce.java",
        "Ed25519.java",
        "Ed25519Sign.java",
        "Ed25519Verify.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":ed25519",
        ":subtle",
        ":x25519",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "@com_google_errorprone_error_prone_annotations",
    ],
)

# hybrid subtle

java_library(
    name = "hybrid",
    srcs = [
        "EciesAeadHkdfDemHelper.java",
        "EciesAeadHkdfHybridDecrypt.java",
        "EciesAeadHkdfHybridEncrypt.java",
        "EciesHkdfRecipientKem.java",
        "EciesHkdfSenderKem.java",
        "Hkdf.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":aead",
        ":subtle",
        ":x25519",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "@com_google_errorprone_error_prone_annotations",
    ],
)

# Streaming

java_library(
    name = "streaming",
    srcs = [
        "AesCtrHmacStreaming.java",
        "AesGcmHkdfStreaming.java",
        "Hkdf.java",
        "NonceBasedStreamingAead.java",
        "RewindableReadableByteChannel.java",
        "StreamSegmentDecrypter.java",
        "StreamSegmentEncrypter.java",
        "StreamingAeadDecryptingChannel.java",
        "StreamingAeadDecryptingStream.java",
        "StreamingAeadEncryptingChannel.java",
        "StreamingAeadEncryptingStream.java",
        "StreamingAeadSeekableDecryptingChannel.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink:primitives",
        "//java/src/main/java/com/google/crypto/tink/annotations",
        "@com_google_code_findbugs_jsr305",
        "@com_google_errorprone_error_prone_annotations",
    ],
)

# x25519 subtle

java_library(
    name = "x25519",
    srcs = [
        "Curve25519.java",
        "Field25519.java",
        "X25519.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/crypto/tink/annotations",
    ],
)

# Ed25519 subtle

java_library(
    name = "ed25519",
    srcs = [
        "Ed25519.java",
        "Ed25519Constants.java",
    ],
    javacopts = JAVACOPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":subtle",
        ":x25519",
        "//java/src/main/java/com/google/crypto/tink/annotations",
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
