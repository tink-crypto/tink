licenses(["notice"])  # Apache 2.0

JAVACOPTS = [
    "-Xlint:unchecked",
    "-Xlint:deprecation",
]

KEYSET_HANDLE_RESTRICTED_API_SRCS = [
    # Storing keyset in cleartext usually leads to security incidents.
    # To discourage users from doing that, the visibility of
    # CleartextKeysetHandle, which allows loading cleartext keyset,
    # is restricted.
    "src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandle.java",
    "src/main/java/com/google/cloud/crypto/tink/AndroidCleartextKeysetHandle.java",
]

KEY_MANAGEMENT_RESTRICTED_API_SRCS = [
    # Normal users should not use this API directly, thus this is restricted.
    "src/main/java/com/google/cloud/crypto/tink/KeysetManager.java",
]

# public interfaces

java_library(
    name = "public_interfaces",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/Aead.java",
        "src/main/java/com/google/cloud/crypto/tink/HybridDecrypt.java",
        "src/main/java/com/google/cloud/crypto/tink/HybridEncrypt.java",
        "src/main/java/com/google/cloud/crypto/tink/Mac.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeySign.java",
        "src/main/java/com/google/cloud/crypto/tink/PublicKeyVerify.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "@com_google_guava//jar",
    ],
)

# common subtle

java_library(
    name = "common_subtle",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/Random.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/SubtleUtil.java",
    ],
    javacopts = JAVACOPTS,
)
# core, without restricted APIs

filegroup(
    name = "core_srcs",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/*.java",
        ],
        exclude = KEYSET_HANDLE_RESTRICTED_API_SRCS +
                  KEY_MANAGEMENT_RESTRICTED_API_SRCS,
    ),
)

java_library(
    name = "core",
    srcs = [":core_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java:common_subtle",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
    ],
)

# excluded from Android because they need com.google.protobuf.TextFormat which is
# not available on Android.
ANDROID_EXCLUDE_SRCS = [
    "src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandle.java",
    "src/main/java/com/google/cloud/crypto/tink/KmsEncryptedKeysetHandle.java",
]

ANDROID_RESTRICTED_SRCS = [
    "src/main/java/com/google/cloud/crypto/tink/AndroidCleartextKeysetHandle.java",
]

filegroup(
    name = "core_android_srcs",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/*.java",
        ],
        exclude = KEYSET_HANDLE_RESTRICTED_API_SRCS +
                  KEY_MANAGEMENT_RESTRICTED_API_SRCS +
                  ANDROID_EXCLUDE_SRCS +
                  ANDROID_RESTRICTED_SRCS,
    ),
)

COMMON_JAVA_DEPS = [
    "//java:common_subtle",
    "//java:core",
    "//proto:java_core",
]

# aead

java_library(
    name = "aead_subtle",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/subtle/AeadBase.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/AesCtrJceCipher.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/AesEaxJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/AesGcmJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EncryptThenAuthenticate.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/IndCpaCipher.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java:common_subtle",
        "//java:public_interfaces",
        "@com_google_guava//jar",
    ],
)

AEAD_ENVELOPE_SRCS = [
    "src/main/java/com/google/cloud/crypto/tink/aead/GoogleCloudKmsAeadKeyManager.java",
    "src/main/java/com/google/cloud/crypto/tink/aead/GoogleCredentialFactory.java",
    "src/main/java/com/google/cloud/crypto/tink/subtle/AeadBase.java",
    "src/main/java/com/google/cloud/crypto/tink/subtle/GoogleCloudKmsAead.java",
]

filegroup(
    name = "aead_srcs",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/aead/*.java",
        ],
        exclude = AEAD_ENVELOPE_SRCS,
    ),
)

java_library(
    name = "aead",
    srcs = [":aead_srcs"],
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:aead_subtle",
        "//java:mac",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_aes_eax",
        "//proto:java_core_compile_imports",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
    ],
)

java_library(
    name = "aead_envelope",
    srcs = AEAD_ENVELOPE_SRCS,
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//proto:java_core_compile_imports",
        "//proto:java_googlecloudkms",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
    ],
)

# mac

java_library(
    name = "mac_subtle",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/subtle/MacJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java:common_subtle",
        "//java:public_interfaces",
    ],
)

filegroup(
    name = "mac_srcs",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/mac/*.java",
        ],
    ),
)

java_library(
    name = "mac",
    srcs = [":mac_srcs"],
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:mac_subtle",
        "//proto:java_core_compile_imports",
        "//proto:java_hmac",
    ],
)

# signature

java_library(
    name = "signature_subtle",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcdsaSignJce.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcdsaVerifyJce.java",
    ],
    javacopts = JAVACOPTS,
    deps = [
        "//java:public_interfaces",
    ],
)

filegroup(
    name = "signature_srcs",
    srcs = glob(
        [
            "src/main/java/com/google/cloud/crypto/tink/signature/*.java",
        ],
    ),
)

java_library(
    name = "signature",
    srcs = [":signature_srcs"],
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:signature_subtle",
        "//proto:java_core_compile_imports",
        "//proto:java_ecdsa",
    ],
)

# hybrid

filegroup(
    name = "hybridencrypt_srcs",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfAeadFactory.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfHybridEncrypt.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfPublicKeyManager.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/HybridEncryptFactory.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/HybridUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EciesHkdfSenderKem.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/Hkdf.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/HybridEncryptBase.java",
    ],
)

java_library(
    name = "hybridencrypt",
    srcs = [
        ":hybridencrypt_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:aead",
        "//java:mac",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_aes_eax",
        "//proto:java_core_compile_imports",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "@com_google_guava//jar",
    ],
)

filegroup(
    name = "hybriddecrypt_srcs",
    srcs = [
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfAeadFactory.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfHybridDecrypt.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/EciesAeadHkdfPrivateKeyManager.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/HybridDecryptFactory.java",
        "src/main/java/com/google/cloud/crypto/tink/hybrid/HybridUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EcUtil.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/EciesHkdfRecipientKem.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/Hkdf.java",
        "src/main/java/com/google/cloud/crypto/tink/subtle/HybridDecryptBase.java",
    ],
)

java_library(
    name = "hybriddecrypt",
    srcs = [
        ":hybriddecrypt_srcs",
    ],
    javacopts = JAVACOPTS,
    deps = COMMON_JAVA_DEPS + [
        "//java:aead",
        "//java:mac",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_aes_eax",
        "//proto:java_core_compile_imports",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "@com_google_guava//jar",
    ],
)

# public library

java_library(
    name = "tink",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:aead",
        "//java:aead_envelope",
        "//java:aead_subtle",
        "//java:common_subtle",
        "//java:core",
        "//java:hybriddecrypt",
        "//java:hybridencrypt",
        "//java:mac",
        "//java:mac_subtle",
        "//java:signature",
        "//java:signature_subtle",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_eax",
        "//proto:java_aes_gcm",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
        "//proto:java_ecdsa",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_googlecloudkms",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
    ],
)

# public hybrid library

java_library(
    name = "tink_hybridencrypt",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:aead",
        "//java:aead_subtle",
        "//java:common_subtle",
        "//java:hybridencrypt",
        "//java:mac",
        "//java:mac_subtle",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_eax",
        "//proto:java_aes_gcm",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
    ],
)

java_library(
    name = "tink_hybriddecrypt",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:aead",
        "//java:aead_subtle",
        "//java:common_subtle",
        "//java:hybriddecrypt",
        "//java:mac",
        "//java:mac_subtle",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_gcm",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
        "//proto:java_ecies_aead_hkdf",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
    ],
)

# public signature library

java_library(
    name = "tink_signature",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//java:signature",
        "//java:signature_subtle",
        "//proto:java_core",
        "//proto:java_core_compile_imports",
        "//proto:java_ecdsa",
    ],
)

# restricted APIs

java_library(
    name = "keyset_handle_restricted",
    srcs = KEYSET_HANDLE_RESTRICTED_API_SRCS,
    javacopts = JAVACOPTS,
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    deps = COMMON_JAVA_DEPS + [
        "//proto:java_core_compile_imports",
    ],
)

java_library(
    name = "key_management_restricted",
    srcs = KEY_MANAGEMENT_RESTRICTED_API_SRCS,
    javacopts = JAVACOPTS,
    visibility = [
        "//examples/java/envelopeme:__pkg__",
        "//tools/tinkey:__pkg__",
    ],
    deps = COMMON_JAVA_DEPS + [
        "//proto:java_core_compile_imports",
    ],
)

# tests

load("//tools:gen_java_test_rules.bzl", "gen_java_test_rules")

java_library(
    name = "generator_test",
    testonly = 1,
    srcs = glob([
        "src/test/java/**/*.java",
    ]),
    deps = [
        "//java:key_management_restricted",
        "//java:keyset_handle_restricted",
        "//java:tink",
        "@com_fasterxml_jackson_core//jar",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@junit_junit_4//jar",
    ],
)

gen_java_test_rules(
    small_tests = glob([
        "src/test/java/**/*ProtoTest.java",
    ]),
    test_files = glob([
        "src/test/java/**/*Test.java",
    ]),
    deps = [
        ":generator_test",
    ],
)
