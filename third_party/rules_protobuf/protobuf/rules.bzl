"""Compiles protobuf for ObjC.

"""

load(
    "//third_party/rules_protobuf/protobuf:internal/proto_compile.bzl",
    _proto_compile = "proto_compile",
)
load(
    "//third_party/rules_protobuf/protobuf:internal/proto_language.bzl",
    _proto_language = "proto_language",
    _proto_language_deps = "proto_language_deps",
)

proto_compile = _proto_compile
proto_language = _proto_language
proto_language_deps = _proto_language_deps
