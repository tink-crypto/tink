package(
    default_visibility = [
        "//cc:__subpackages__",
        "//java:__subpackages__",
        "//objc:__subpackages__",
    ],
)

licenses(["notice"])  # Apache 2.0

load("//third_party/rules_protobuf/javalite:rules.bzl", "java_lite_proto_library")

# common
proto_library(
    name = "common",
    srcs = [
        "common.proto",
    ],
)

cc_proto_library(
    name = "common_cc_proto",
    deps = [":common"],
)

java_proto_library(
    name = "common_java_proto",
    deps = [":common"],
)

java_lite_proto_library(
    name = "common_java_proto_lite",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

# tink
proto_library(
    name = "tink",
    srcs = [
        "tink.proto",
    ],
    deps = [
        ":common",
    ],
)

cc_proto_library(
    name = "tink_cc_proto",
    deps = [":tink"],
)

java_proto_library(
    name = "tink_java_proto",
    deps = [":tink"],
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

# ecdsa
proto_library(
    name = "ecdsa",
    srcs = [
        "ecdsa.proto",
    ],
    deps = [
        ":common",
    ],
)

cc_proto_library(
    name = "ecdsa_cc_proto",
    deps = [":ecdsa"],
)

java_proto_library(
    name = "ecdsa_java_proto",
    deps = [":ecdsa"],
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

# ed25519
proto_library(
    name = "ed25519",
    srcs = [
        "ed25519.proto",
    ],
)

cc_proto_library(
    name = "ed25519_cc_proto",
    deps = [":ed25519"],
)

java_proto_library(
    name = "ed25519_java_proto",
    deps = [":ed25519"],
)

java_lite_proto_library(
    name = "ed25519_java_proto_lite",
    protos = [
        "ed25519.proto",
    ],
    verbose = 0,
)

# hmac
proto_library(
    name = "hmac",
    srcs = [
        "hmac.proto",
    ],
    deps = [":common"],
)

cc_proto_library(
    name = "hmac_cc_proto",
    deps = [":hmac"],
)

java_proto_library(
    name = "hmac_java_proto",
    deps = [":hmac"],
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

# aes_ctr
proto_library(
    name = "aes_ctr",
    srcs = [
        "aes_ctr.proto",
    ],
)

cc_proto_library(
    name = "aes_ctr_cc_proto",
    deps = [":aes_ctr"],
)

java_proto_library(
    name = "aes_ctr_java_proto",
    deps = [":aes_ctr"],
)

java_lite_proto_library(
    name = "aes_ctr_java_proto_lite",
    protos = [
        "aes_ctr.proto",
    ],
    verbose = 0,
)

# aes_ctr_hmac_aead
proto_library(
    name = "aes_ctr_hmac_aead",
    srcs = [
        "aes_ctr_hmac_aead.proto",
    ],
    deps = [
        ":aes_ctr",
        ":hmac",
    ],
)

cc_proto_library(
    name = "aes_ctr_hmac_aead_cc_proto",
    deps = [":aes_ctr_hmac_aead"],
)

java_proto_library(
    name = "aes_ctr_hmac_aead_java_proto",
    deps = [":aes_ctr_hmac_aead"],
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

# aes_gcm
proto_library(
    name = "aes_gcm",
    srcs = [
        "aes_gcm.proto",
    ],
)

cc_proto_library(
    name = "aes_gcm_cc_proto",
    deps = [":aes_gcm"],
)

java_proto_library(
    name = "aes_gcm_java_proto",
    deps = [":aes_gcm"],
)

java_lite_proto_library(
    name = "aes_gcm_java_proto_lite",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

# aes_eax
proto_library(
    name = "aes_eax",
    srcs = [
        "aes_eax.proto",
    ],
)

cc_proto_library(
    name = "aes_eax_cc_proto",
    deps = [":aes_eax"],
)

java_proto_library(
    name = "aes_eax_java_proto",
    deps = [":aes_eax"],
)

java_lite_proto_library(
    name = "aes_eax_java_proto_lite",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

# gcp_kms
proto_library(
    name = "gcp_kms",
    srcs = [
        "gcp_kms.proto",
    ],
)

cc_proto_library(
    name = "gcp_kms_cc_proto",
    deps = [":gcp_kms"],
)

java_proto_library(
    name = "gcp_kms_java_proto",
    deps = [":gcp_kms"],
)

java_lite_proto_library(
    name = "gcp_java_proto_lite",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

# kms_envelope
proto_library(
    name = "kms_envelope",
    srcs = [
        "kms_envelope.proto",
    ],
    deps = [":tink"],
)

cc_proto_library(
    name = "kms_envelope_cc_proto",
    deps = [":kms_envelope"],
)

java_proto_library(
    name = "kms_envelope_java_proto",
    deps = [":kms_envelope"],
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

# ECIES hybrid encryption with AEAD and HKDF
proto_library(
    name = "ecies_aead_hkdf",
    srcs = [
        "ecies_aead_hkdf.proto",
    ],
    deps = [
        ":common",
        ":tink",
    ],
)

cc_proto_library(
    name = "ecies_aead_hkdf_cc_proto",
    deps = [":ecies_aead_hkdf"],
)

java_proto_library(
    name = "ecies_aead_hkdf_java_proto",
    deps = [":ecies_aead_hkdf"],
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
