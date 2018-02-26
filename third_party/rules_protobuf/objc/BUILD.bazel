package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//third_party/rules_protobuf/protobuf:rules.bzl", "proto_language")

proto_language(
    name = "objc",
    output_file_style = "pascal",
    pb_file_extensions = [
        ".pbobjc.h",
        ".pbobjc.m",
    ],
)
