licenses(["notice"])  # Apache 2.0

package(default_visibility = ["//visibility:public"])

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library")

cc_proto_library(
    name = "cc_common",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "common.proto",
    ],
    verbose = 0,
    with_grpc = False,
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
    with_grpc = False,
)

java_proto_library(
    name = "java_tink",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "common.proto",
        "tink.proto",
    ],
    verbose = 0,
    with_grpc = False,
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
    with_grpc = False,
)

java_proto_library(
    name = "java_ecdsa",
    proto_deps = [
        ":java_tink",
    ],
    protos = [
        "ecdsa.proto",
    ],
    verbose = 0,
    with_grpc = False,
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
    with_grpc = False,
)

java_proto_library(
    name = "java_hmac",
    proto_deps = [
        ":java_tink",
    ],
    protos = [
        "hmac.proto",
    ],
    verbose = 0,
    with_grpc = False,
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
    with_grpc = False,
)

java_proto_library(
    name = "java_aes_ctr_hmac_aead",
    proto_deps = [
        ":java_hmac",
    ],
    protos = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

# aes_gcm

cc_proto_library(
    name = "cc_aes_gcm",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_aes_gcm",
    protos = [
        "aes_gcm.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

# aes_eax

cc_proto_library(
    name = "cc_aes_eax",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_aes_eax",
    protos = [
        "aes_eax.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

# googlecloudkms

cc_proto_library(
    name = "cc_googlecloudkms",
    protos = [
        "googlecloudkms.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_googlecloudkms",
    protos = [
        "googlecloudkms.proto",
    ],
    verbose = 0,
    with_grpc = False,
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
    with_grpc = False,
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
    with_grpc = False,
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
    with_grpc = False,
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
        ":java_tink",
    ],
    protos = [
        "ecies_aead_hkdf.proto",
    ],
    verbose = 0,
    with_grpc = False,
)
