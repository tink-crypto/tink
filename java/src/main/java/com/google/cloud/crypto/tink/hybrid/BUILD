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
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybrid",
        "//proto:aes_ctr_hmac_aead_java_proto",
        "//proto:aes_gcm_java_proto",
        "//proto:common_java_proto",
        "//proto:ecies_aead_hkdf_java_proto",
        "//proto:hmac_java_proto",
        "//proto:tink_java_proto",
        "//proto:tink_java_proto_compile_imports",
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
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:hybrid",
        "//proto:aes_ctr_hmac_aead_java_proto",
        "//proto:aes_gcm_java_proto",
        "//proto:common_java_proto",
        "//proto:ecies_aead_hkdf_java_proto",
        "//proto:hmac_java_proto",
        "//proto:tink_java_proto",
        "//proto:tink_java_proto_compile_imports",
    ],
)
