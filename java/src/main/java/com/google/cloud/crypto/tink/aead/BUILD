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
        "//proto:aes_ctr_hmac_aead_java_proto",
        "//proto:aes_eax_java_proto",
        "//proto:aes_gcm_java_proto",
        "//proto:common_java_proto",
        "//proto:hmac_java_proto",
        "//proto:kms_envelope_java_proto",
        "//proto:tink_java_proto",
        "//proto:tink_java_proto_compile_imports",
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
        "//proto:common_java_proto",
        "//proto:gcp_kms_java_proto",
        "//proto:tink_java_proto",
        "//proto:tink_java_proto_compile_imports",
        "@com_google_api_client//jar",
        "@com_google_cloudkms//jar",
        "@com_google_guava//jar",
        "@com_google_http_client//jar",
        "@com_google_http_client_jackson2//jar",
        "@com_google_oauth_client//jar",
    ],
)
