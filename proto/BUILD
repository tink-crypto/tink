package(default_visibility = ["//visibility:public"])

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library")

cc_proto_library(
    name = "cc_core_proto",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "tink.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

cc_proto_library(
    name = "cc_ecdsa_proto",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        "common.proto",
        "ecdsa.proto",
    ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_core_proto",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos =
        [
            "tink.proto",
        ],
    verbose = 0,
    with_grpc = False,
)

java_proto_library(
    name = "java_ecdsa_proto",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos =
        [
            "common.proto",
            "tink.proto",
        ],
    verbose = 0,
    with_grpc = False,
)
