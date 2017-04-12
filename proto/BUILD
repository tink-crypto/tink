package(
    default_visibility = [
        "//cc:__subpackages__",
        "//java:__subpackages__",
    ],
)

licenses(["notice"])  # Apache 2.0

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library")

cc_proto_library(
    name = "cc_common",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

cc_proto_library(
    name = "cc_tink",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        ":cc_common",
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_common",
    protos = [
        "common.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_tink",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        ":java_common",
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
)

# ecdsa

cc_proto_library(
    name = "cc_ecdsa",
    proto_deps = [
        ":cc_common",
        ":cc_tink",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_ecdsa",
    proto_deps = [
        ":java_common",
        ":java_tink",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
)

# hmac

cc_proto_library(
    name = "cc_hmac",
    proto_deps = [
        ":cc_common",
        ":cc_tink",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_hmac",
    proto_deps = [
        ":java_common",
        ":java_tink",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
)

# aes_ctr_hmac_aead

cc_proto_library(
    name = "cc_aes_ctr_hmac_aead",
    proto_deps = [
        ":cc_common",
        ":cc_hmac",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_aes_ctr_hmac_aead",
    proto_deps = [
        ":java_common",
        ":java_hmac",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
)

# aes_gcm

cc_proto_library(
    name = "cc_aes_gcm",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_aes_gcm",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
)

# aes_eax

cc_proto_library(
    name = "cc_aes_eax",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_aes_eax",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
)

# gcp_kms

cc_proto_library(
    name = "cc_gcp_kms",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_gcp_kms",
    protos = [
        "gcp_kms.proto",
    ],
    verbose = 0,
)

# kms_envelope

cc_proto_library(
    name = "cc_kms_envelope",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    proto_deps = [
        ":cc_tink",
    ],
    protos = [
        "kms_envelope.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_kms_envelope",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    proto_deps = [
        ":java_tink",
    ],
    protos = [
        "kms_envelope.proto",
    ],
    verbose = 0,
)

# ECIES hybrid encryption with AEAD and HKDF

cc_proto_library(
    name = "cc_ecies_aead_hkdf",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    proto_deps = [
        ":cc_common",
        ":cc_tink",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
)

java_proto_library(
    name = "java_ecies_aead_hkdf",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    proto_deps = [
        ":java_common",
        ":java_tink",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
)
