"""Compiles protobuf for ObjC.

"""

load("//third_party/rules_protobuf/protobuf:rules.bzl", "proto_compile")

def objc_proto_compile(
    langs = [str(Label("//third_party/rules_protobuf/objc"))],
    **kwargs):
  proto_compile(langs = langs, **kwargs)
