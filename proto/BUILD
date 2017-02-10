package(default_visibility = ["//visibility:public"])

load("@org_pubref_rules_protobuf//cpp:rules.bzl", "cc_proto_library")
load("@org_pubref_rules_protobuf//java:rules.bzl", "java_proto_library")

filegroup(
    name = "core",
    srcs = ["tink.proto"],
)

filegroup(
    name = "ecdsa",
    srcs = [
        "common.proto",
        "ecdsa.proto",
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

cc_proto_library(
    name = "cc_ecdsa",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        ":ecdsa",
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

java_proto_library(
    name = "java_ecdsa",
    imports = [
        "external/com_github_google_protobuf/src/",
    ],
    inputs = [
        "@com_github_google_protobuf//:well_known_protos",
    ],
    protos = [
        ":ecdsa",
    ],
    verbose = 0,
    with_grpc = False,
)
