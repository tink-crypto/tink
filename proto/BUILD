package(default_visibility = ["//visibility:public"])

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library")

filegroup(
    name = "core",
    srcs = [
        "common.proto",
        "tink.proto",
    ],
)

cc_proto_library(
    name = "cc_core",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        ":core",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_core",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        ":core",
    ],
    verbose = 0,
    with_grpc = False,
)

# ecdsa

filegroup(
    name = "ecdsa",
    srcs = [
        "ecdsa.proto",
    ],
)

cc_proto_library(
    name = "cc_ecdsa",
    proto_deps = [
        ":cc_core",
    ],
    protos = [
        ":ecdsa",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_ecdsa",
    proto_deps = [
        ":java_core",
    ],
    protos = [
        ":ecdsa",
    ],
    verbose = 0,
    with_grpc = False,
)

# hmac

filegroup(
    name = "hmac",
    srcs = [
        "hmac.proto",
    ],
)

cc_proto_library(
    name = "cc_hmac",
    proto_deps = [
        ":cc_core",
    ],
    protos = [
        ":hmac",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_hmac",
    proto_deps = [
        ":java_core",
    ],
    protos = [
        ":hmac",
    ],
    verbose = 0,
    with_grpc = False,
)

# aes_ctr_hmac_aead

filegroup(
    name = "aes_ctr_hmac_aead",
    srcs = [
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
    ],
)

cc_proto_library(
    name = "cc_aes_ctr_hmac_aead",
    proto_deps = [
        ":cc_hmac",
    ],
    protos = [
        ":aes_ctr_hmac_aead",
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
        ":aes_ctr_hmac_aead",
    ],
    verbose = 0,
    with_grpc = False,
)

# aes_gcm

filegroup(
    name = "aes_gcm",
    srcs = [
        "aes_gcm.proto",
    ],
)

cc_proto_library(
    name = "cc_aes_gcm",
    protos = [
        ":aes_gcm",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_aes_gcm",
    protos = [
        ":aes_gcm",
    ],
    verbose = 0,
    with_grpc = False,
)

# googlecloudkms

filegroup(
    name = "googlecloudkms",
    srcs = [
        "googlecloudkms.proto",
    ],
)

cc_proto_library(
    name = "cc_googlecloudkms",
    protos = [
        ":googlecloudkms",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_googlecloudkms",
    protos = [
        ":googlecloudkms",
    ],
    verbose = 0,
    with_grpc = False,
)
