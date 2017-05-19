# Bazel Skylark rules for building lite protos for Java

This is a minimal fork of [Rules Protobuf](https://github.com/pubref/rules_protobuf)
that supports generating lite protos for Java.

Tink needs temporarily depend on these rules because java_lite_proto_library is
not working properly. See https://github.com/cgrushko/proto_library/issues/1.

Once either Bazel or Protobuf team fixes java_lite_proto_library, these rules
can be removed.
