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
    name = "aead",
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
    name = "aead_envelope",
    srcs = [
        "AeadBase.java",
        "GcpKmsAead.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
    ],
)

# Google credential subtle

java_library(
    name = "gcp_credential",
    srcs = [
        "GcpCredentialFactory.java",
        "GcpScopes.java",
        "ServiceAccountGcpCredentialFactory.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "@com_google_api_client//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
        "@com_google_oauth_client//jar",
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
        "//java/src/main/java/com/google/cloud/crypto/tink:primitives",
    ],
)

# signature subtle

java_library(
    name = "signature",
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

# hybrid subtle

java_library(
    name = "hybrid",
    srcs = [
        "EcUtil.java",
        "EciesHkdfRecipientKem.java",
        "EciesHkdfSenderKem.java",
        "Hkdf.java",
        "HybridDecryptBase.java",
        "HybridEncryptBase.java",
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
    name = "x25519",
    srcs = [
        "Curve25519.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        ":subtle",
        "@com_google_guava//jar",
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
