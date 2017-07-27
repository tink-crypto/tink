package(
    default_visibility = [
        "//cc:__subpackages__",
        "//go:__subpackages__",
        "//java:__subpackages__",
        "//objc:__subpackages__",
    ],
)

licenses(["notice"])  # Apache 2.0

load("@io_bazel_rules_go//proto:go_proto_library.bzl", "go_proto_library")

# -----------------------------------------------
# common
# -----------------------------------------------
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
    deps = [":common"],
)

go_proto_library(
    name = "common_go_proto",
    srcs = [
        "common.proto",
    ],
)

# -----------------------------------------------
# tink
# -----------------------------------------------
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
    deps = [":tink"],
)

go_proto_library(
    name = "tink_go_proto",
    srcs = [
        "tink.proto",
    ],
    deps = [
        ":common_go_proto",
    ],
)

# -----------------------------------------------
# ecdsa
# -----------------------------------------------
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
    deps = [":ecdsa"],
)

go_proto_library(
    name = "ecdsa_go_proto",
    srcs = [
        "ecdsa.proto",
    ],
    deps = [
        ":common_go_proto",
    ],
)

# -----------------------------------------------
# ed25519
# -----------------------------------------------
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
    deps = [":ed25519"],
)

go_proto_library(
    name = "ed25519_go_proto",
    srcs = [
        "ed25519.proto",
    ],
)

# -----------------------------------------------
# hmac
# -----------------------------------------------
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
    deps = [":hmac"],
)

go_proto_library(
    name = "hmac_go_proto",
    srcs = [
        "hmac.proto",
    ],
    deps = [
        ":common_go_proto",
    ],
)

# -----------------------------------------------
# aes_ctr
# -----------------------------------------------
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
    deps = [":aes_ctr"],
)

go_proto_library(
    name = "aes_ctr_go_proto",
    srcs = [
        "aes_ctr.proto",
    ],
)

# -----------------------------------------------
# aes_ctr_hmac_aead
# -----------------------------------------------
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
    deps = [":aes_ctr_hmac_aead"],
)

go_proto_library(
    name = "aes_ctr_hmac_aead_go_proto",
    srcs = [
        "aes_ctr_hmac_aead.proto",
    ],
    deps = [
        ":aes_ctr_go_proto",
        ":hmac_go_proto",
    ],
)

# -----------------------------------------------
# aes_gcm
# -----------------------------------------------
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
    deps = [":aes_gcm"],
)

go_proto_library(
    name = "aes_gcm_go_proto",
    srcs = [
        "aes_gcm.proto",
    ],
)

# -----------------------------------------------
# aes_ctr_hmac_streaming
# -----------------------------------------------
proto_library(
    name = "aes_ctr_hmac_streaming",
    srcs = ["aes_ctr_hmac_streaming.proto"],
    deps = [
        ":common",
        ":hmac",
    ],
)

cc_proto_library(
    name = "aes_ctr_hmac_streaming_cc_proto",
    deps = [":aes_ctr_hmac_streaming"],
)

java_proto_library(
    name = "aes_ctr_hmac_streaming_java_proto",
    deps = [":aes_ctr_hmac_streaming"],
)

java_lite_proto_library(
    name = "aes_ctr_hmac_streaming_java_proto_lite",
    deps = [":aes_ctr_hmac_streaming"],
)

go_proto_library(
    name = "aes_ctr_hmac_streaming_go_proto",
    srcs = [
        "aes_ctr_hmac_streaming.proto",
    ],
    deps = [
        ":common_go_proto",
        ":hmac_go_proto",
    ],
)

# -----------------------------------------------
# aes_gcm_hkdf_streaming
# -----------------------------------------------
proto_library(
    name = "aes_gcm_hkdf_streaming",
    srcs = ["aes_gcm_hkdf_streaming.proto"],
    deps = [":common"],
)

cc_proto_library(
    name = "aes_gcm_hkdf_streaming_cc_proto",
    deps = [":aes_gcm_hkdf_streaming"],
)

java_proto_library(
    name = "aes_gcm_hkdf_streaming_java_proto",
    deps = [":aes_gcm_hkdf_streaming"],
)

java_lite_proto_library(
    name = "aes_gcm_hkdf_streaming_java_proto_lite",
    deps = [":aes_gcm_hkdf_streaming"],
)

go_proto_library(
    name = "aes_gcm_hkdf_streaming_go_proto",
    srcs = [
        "aes_gcm_hkdf_streaming.proto",
    ],
    deps = [
        ":common_go_proto",
    ],
)

# -----------------------------------------------
# aes_eax
# -----------------------------------------------
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
    deps = [":aes_eax"],
)

go_proto_library(
    name = "aes_eax_go_proto",
    srcs = [
        "aes_eax.proto",
    ],
)

# -----------------------------------------------
# chacha20_poly1305
# -----------------------------------------------
proto_library(
    name = "chacha20_poly1305",
    srcs = [
        "chacha20_poly1305.proto",
    ],
)

cc_proto_library(
    name = "chacha20_poly1305_cc_proto",
    deps = [":chacha20_poly1305"],
)

java_proto_library(
    name = "chacha20_poly1305_java_proto",
    deps = [":chacha20_poly1305"],
)

java_lite_proto_library(
    name = "chacha20_poly1305_java_proto_lite",
    deps = [":chacha20_poly1305"],
)

go_proto_library(
    name = "chacha20_poly1305_go_proto",
    srcs = [
        "chacha20_poly1305.proto",
    ],
)

# -----------------------------------------------
# gcp_kms
# -----------------------------------------------
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
    name = "gcp_kms_java_proto_lite",
    deps = [":gcp_kms"],
)

go_proto_library(
    name = "gcp_kms_go_proto",
    srcs = [
        "gcp_kms.proto",
    ],
)

# -----------------------------------------------
# kms_envelope
# -----------------------------------------------
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
    deps = [":kms_envelope"],
)

go_proto_library(
    name = "kms_envelope_go_proto",
    srcs = [
        "kms_envelope.proto",
    ],
    deps = [
        ":tink_go_proto",
    ],
)

# -----------------------------------------------
# ecies_aead_hkdf
# -----------------------------------------------
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
    deps = [":ecies_aead_hkdf"],
)

go_proto_library(
    name = "ecies_aead_hkdf_go_proto",
    srcs = [
        "ecies_aead_hkdf.proto",
    ],
    deps = [
        ":common_go_proto",
        ":tink_go_proto",
    ],
)
