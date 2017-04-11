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

AEAD_ENVELOPE_SRCS = [
    "GcpKmsAeadKeyManager.java",
]

filegroup(
    name = "aead_srcs",
    srcs = glob(
        [
            "*.java",
        ],
        exclude = AEAD_ENVELOPE_SRCS,
    ),
)

java_library(
    name = "aead",
    srcs = [":aead_srcs"],
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/mac",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:aead",
        "//proto:java_aes_ctr_hmac_aead",
        "//proto:java_aes_eax",
        "//proto:java_aes_gcm",
        "//proto:java_common",
        "//proto:java_hmac",
        "//proto:java_kms_envelope",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
    ],
)

java_library(
    name = "aead_envelope",
    srcs = AEAD_ENVELOPE_SRCS,
    javacopts = JAVACOPTS,
    deps = [
        "//java/src/main/java/com/google/cloud/crypto/tink",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:aead_envelope",
        "//java/src/main/java/com/google/cloud/crypto/tink/subtle:gcp_credential",
        "//proto:java_common",
        "//proto:java_gcp_kms",
        "//proto:java_tink",
        "//proto:java_tink_compile_imports",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
    ],
)
