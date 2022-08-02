# C++ Digital Signatures CLI

This is a command-line tool that can generate
[Digital Signature](../../../docs/PRIMITIVES.md#digital-signatures)
keys, and create and verify digital signatures.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/cc/examples
bazel build ...
echo "a message" > message.txt
./bazel-bin/digital_signatures/digital_signatures_cli gen-private-key private_keyset.bin
./bazel-bin/digital_signatures/digital_signatures_cli get-public-key private_keyset.bin \
    public_keyset.bin
./bazel-bin/digital_signatures/digital_signatures_cli sign private_keyset.bin \
    message.txt signature.bin
./bazel-bin/digital_signatures/digital_signatures_cli verify public_keyset.bin \
    message.txt signature.bin result.txt
cat result.txt
```
