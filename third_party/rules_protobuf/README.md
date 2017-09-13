# Bazel Skylark rules for building protobufs for ObjC

This is a minimal fork of [Rules Protobuf](https://github.com/pubref/rules_protobuf)
that supports building protobuf for ObjC.

Tink needs temporarily depend on these rules because objc_proto_library is
not working properly. See https://github.com/bazelbuild/bazel/issues/1802.

Once either Bazel or Protobuf team fixes objc_proto_library, these rules
can be removed.
