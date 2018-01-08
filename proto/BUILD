package(default_visibility = ["//tools/build_defs:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("@io_bazel_rules_go//proto:go_proto_library.bzl", "go_proto_library")
load("//third_party/rules_protobuf/objc:rules.bzl", "objc_proto_compile")
load("//proto:objc.bzl", "tink_objc_proto_library")

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

objc_proto_compile(
    name = "common_objc_pb",
    protos = ["common.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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
    ignore_go_package_option = 1,
    deps = [
        ":common_go_proto",
    ],
)

objc_proto_compile(
    name = "tink_objc_pb",
    protos = ["tink.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
)

# -----------------------------------------------
# config
# -----------------------------------------------
proto_library(
    name = "config",
    srcs = [
        "config.proto",
    ],
)

cc_proto_library(
    name = "config_cc_proto",
    deps = [":config"],
)

java_proto_library(
    name = "config_java_proto",
    deps = [":config"],
)

java_lite_proto_library(
    name = "config_java_proto_lite",
    deps = [":config"],
)

go_proto_library(
    name = "config_go_proto",
    srcs = [
        "config.proto",
    ],
    deps = [
        ":common_go_proto",
    ],
)

# -----------------------------------------------
# aes-siv
# -----------------------------------------------
proto_library(
    name = "aes_siv",
    srcs = [
        "aes_siv.proto",
    ],
)

cc_proto_library(
    name = "aes_siv_cc_proto",
    deps = [":aes_siv"],
)

java_proto_library(
    name = "aes_siv_java_proto",
    deps = [":aes_siv"],
)

java_lite_proto_library(
    name = "aes_siv_java_proto_lite",
    deps = [":aes_siv"],
)

go_proto_library(
    name = "aes_siv_go_proto",
    srcs = [
        "aes_siv.proto",
    ],
)

objc_proto_compile(
    name = "aes_siv_objc_pb",
    protos = ["aes_siv.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "ecdsa_objc_pb",
    protos = ["ecdsa.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [":common_objc_pb"],
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

objc_proto_compile(
    name = "ed25519_objc_pb",
    protos = ["ed25519.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "hmac_objc_pb",
    protos = ["hmac.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [":common_objc_pb"],
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

objc_proto_compile(
    name = "aes_ctr_objc_pb",
    protos = ["aes_ctr.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "aes_ctr_hmac_aead_objc_pb",
    protos = ["aes_ctr_hmac_aead.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [
        ":aes_ctr_objc_pb",
        ":hmac_objc_pb",
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

objc_proto_compile(
    name = "aes_gcm_objc_pb",
    protos = ["aes_gcm.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "aes_ctr_hmac_streaming_objc_pb",
    protos = ["aes_ctr_hmac_streaming.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [
        ":common_objc_pb",
        ":hmac_objc_pb",
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

objc_proto_compile(
    name = "aes_gcm_hkdf_streaming_objc_pb",
    protos = ["aes_gcm_hkdf_streaming.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [
        ":common_objc_pb",
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

objc_proto_compile(
    name = "aes_eax_objc_pb",
    protos = ["aes_eax.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "chacha20_poly1305_objc_pb",
    protos = ["chacha20_poly1305.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
)

# -----------------------------------------------
# kms_aead
# -----------------------------------------------
proto_library(
    name = "kms_aead",
    srcs = [
        "kms_aead.proto",
    ],
)

cc_proto_library(
    name = "kms_aead_cc_proto",
    deps = [":kms_aead"],
)

java_proto_library(
    name = "kms_aead_java_proto",
    deps = [":kms_aead"],
)

java_lite_proto_library(
    name = "kms_aead_java_proto_lite",
    deps = [":kms_aead"],
)

go_proto_library(
    name = "kms_aead_go_proto",
    srcs = [
        "kms_aead.proto",
    ],
)

objc_proto_compile(
    name = "kms_aead_objc_pb",
    protos = ["kms_aead.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
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

objc_proto_compile(
    name = "kms_envelope_objc_pb",
    protos = ["kms_envelope.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [
        ":tink_objc_pb",
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

objc_proto_compile(
    name = "ecies_aead_hkdf_objc_pb",
    protos = ["ecies_aead_hkdf.proto"],
    tags = ["manual"],
    visibility = ["//visibility:private"],
    deps = [
        ":common_objc_pb",
        ":tink_objc_pb",
    ],
)

# -----------------------------------------------
# objc library
# -----------------------------------------------
tink_objc_proto_library(
    name = "all_objc_proto",
    srcs = [
        ":aes_ctr_hmac_aead_objc_pb",
        ":aes_ctr_hmac_streaming_objc_pb",
        ":aes_ctr_objc_pb",
        ":aes_eax_objc_pb",
        ":aes_gcm_hkdf_streaming_objc_pb",
        ":aes_gcm_objc_pb",
        ":chacha20_poly1305_objc_pb",
        ":common_objc_pb",
        ":ecdsa_objc_pb",
        ":ecies_aead_hkdf_objc_pb",
        ":ed25519_objc_pb",
        ":hmac_objc_pb",
        ":kms_aead_objc_pb",
        ":kms_envelope_objc_pb",
        ":tink_objc_pb",
    ],
    tags = ["manual"],
)
