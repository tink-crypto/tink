package(
    default_visibility = [
        "//cc:__subpackages__",
        "//java:__subpackages__",
    ],
)

licenses(["notice"])  # Apache 2.0

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library", "java_lite_proto_library")

# common
cc_proto_library(
    name = "common_cc_proto",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "common_java_proto_lite",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "common_java_proto",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

# tink
cc_proto_library(
    name = "tink_cc_proto",
    inputs = [
        ":common_cc_proto",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "tink_java_proto_lite",
    inputs = [
        ":common_java_proto_lite",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "tink_java_proto",
    inputs = [
        ":common_java_proto",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
)

# ecdsa
cc_proto_library(
    name = "ecdsa_cc_proto",
    proto_deps = [
        ":common_cc_proto",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "ecdsa_java_proto_lite",
    proto_deps = [
        ":common_java_proto_lite",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "ecdsa_java_proto",
    proto_deps = [
        ":common_java_proto",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
)

# ed25519
cc_proto_library(
    name = "ed25519_cc_proto",
    protos = [
        "ed25519.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "ed25519_java_proto_lite",
    protos = [
        "ed25519.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "ed25519_java_proto",
    protos = [
        "ed25519.proto",
    ],
    verbose = 0,
)

# hmac
cc_proto_library(
    name = "hmac_cc_proto",
    proto_deps = [
        ":common_cc_proto",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "hmac_java_proto_lite",
    proto_deps = [
        ":common_java_proto_lite",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "hmac_java_proto",
    proto_deps = [
        ":common_java_proto",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
)

# aes_ctr_hmac_aead
cc_proto_library(
    name = "aes_ctr_hmac_aead_cc_proto",
    proto_deps = [
        ":common_cc_proto",
        ":hmac_cc_proto",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "aes_ctr_hmac_aead_java_proto_lite",
    proto_deps = [
        ":common_java_proto_lite",
        ":hmac_java_proto_lite",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "aes_ctr_hmac_aead_java_proto",
    proto_deps = [
        ":common_java_proto",
        ":hmac_java_proto",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
)

# aes_gcm
cc_proto_library(
    name = "aes_gcm_cc_proto",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "aes_gcm_java_proto_lite",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "aes_gcm_java_proto",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

# aes_eax
cc_proto_library(
    name = "aes_eax_cc_proto",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "aes_eax_java_proto_lite",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "aes_eax_java_proto",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

# gcp_kms
cc_proto_library(
    name = "gcp_kms_cc_proto",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "gcp_java_proto_lite",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "gcp_kms_java_proto",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

# kms_envelope
cc_proto_library(
    name = "kms_envelope_cc_proto",
    proto_deps = [
        ":tink_cc_proto",
    ],
    protos = [
        "kms_envelope.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "kms_envelope_java_proto_lite",
    proto_deps = [
        ":tink_java_proto_lite",
    ],
    protos = [
        "kms_envelope.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "kms_envelope_java_proto",
    proto_deps = [
        ":tink_java_proto",
    ],
    protos = [
        "kms_envelope.proto",
    ],
    verbose = 0,
)

# ECIES hybrid encryption with AEAD and HKDF
cc_proto_library(
    name = "ecies_aead_hkdf_cc_proto",
    proto_deps = [
        ":common_cc_proto",
        ":tink_cc_proto",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
)

java_lite_proto_library(
    name = "ecies_aead_hkdf_java_proto_lite",
    proto_deps = [
        ":common_java_proto_lite",
        ":tink_java_proto_lite",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "ecies_aead_hkdf_java_proto",
    proto_deps = [
        ":common_java_proto",
        ":tink_java_proto",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
)
