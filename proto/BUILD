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
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
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
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
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
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
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
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    proto_deps = [
        ":java_core",
    ],
    protos = [
        ":hmac",
    ],
    verbose = 0,
    with_grpc = False,
)
