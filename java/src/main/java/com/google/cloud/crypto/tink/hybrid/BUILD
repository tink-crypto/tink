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

filegroup(
    name = "hybridencrypt_srcs",
    srcs = [
        "EciesAeadHkdfAeadFactory.java",
        "EciesAeadHkdfHybridEncrypt.java",
        "EciesAeadHkdfPublicKeyManager.java",
        "HybridEncryptFactory.java",
        "HybridUtil.java",
    ],
)

java_library(
    name = "hybridencrypt",
    srcs = [
        ":hybridencrypt_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/aead",
        "//java/src/main/java/com/google/cloud/crypto/tink/mac",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybridencrypt",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_common",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)

filegroup(
    name = "hybriddecrypt_srcs",
    srcs = [
        "EciesAeadHkdfAeadFactory.java",
        "EciesAeadHkdfHybridDecrypt.java",
        "EciesAeadHkdfPrivateKeyManager.java",
        "HybridDecryptFactory.java",
        "HybridUtil.java",
    ],
)

java_library(
    name = "hybriddecrypt",
    srcs = [
        ":hybriddecrypt_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/aead",
        "//java/src/main/java/com/google/cloud/crypto/tink/mac",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybriddecrypt",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_common",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)
