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

# common subtle

java_library(
    name = "subtle",
    srcs = [
        "EcUtil.java",
        "EngineFactory.java",
        "EngineWrapper.java",
        "Random.java",
        "SubtleUtil.java",
    ],
    javacopts = JAVACOPTS,
)

# aead subtle

java_library(
    name = "aead_subtle",
    srcs = [
        "AeadBase.java",
        "AesCtrJceCipher.java",
        "AesEaxJce.java",
        "AesGcmJce.java",
        "EncryptThenAuthenticate.java",
        "IndCpaCipher.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
        "@com_google_guava//jar",
    ],
)

# aead envelope subtle

java_library(
    name = "aead_envelope_subtle",
    srcs = [
        "AeadBase.java",
        "GoogleCloudKmsAead.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
    ],
)

# mac subtle

java_library(
    name = "mac_subtle",
    srcs = [
        "MacJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
    ],
)

# signature subtle

java_library(
    name = "signature_subtle",
    srcs = [
        "EcUtil.java",
        "EcdsaSignJce.java",
        "EcdsaVerifyJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
    ],
)

# hybridencrypt subtle

java_library(
    name = "hybridencrypt_subtle",
    srcs = [
        "EcUtil.java",
        "EciesHkdfSenderKem.java",
        "Hkdf.java",
        "HybridEncryptBase.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
        "@com_google_guava//jar",
    ],
)

# hybriddecrypt subtle

java_library(
    name = "hybriddecrypt_subtle",
    srcs = [
        "EcUtil.java",
        "EciesHkdfRecipientKem.java",
        "Hkdf.java",
        "HybridDecryptBase.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
        "@com_google_guava//jar",
    ],
)

# x25519 subtle

java_library(
    name = "x25519_subtle",
    srcs = [
        "Curve25519.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
    ],
)
