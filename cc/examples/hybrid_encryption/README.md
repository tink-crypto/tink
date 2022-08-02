# C++ Hybrid Encryption CLI

This is a command-line tool that can generate
[Hybrid Encryption](../../../docs/PRIMITIVES.md#hybrid_encryption) keys, and
encrypt and decrypt using Hybrid encryption.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/cc/examples
bazel build ...
echo "a message" > message.txt
echo "context" > context_info.txt
./bazel-bin/hybrid_encryption/hybrid_encryption_cli gen-private-key private_keyset.bin
./bazel-bin/hybrid_encryption/hybrid_encryption_cli get-public-key private_keyset.bin \
    public_keyset.bin
./bazel-bin/hybrid_encryption/hybrid_encryption_cli encrypt public_keyset.bin \
    message.txt context_info.txt encrypted_message.bin
./bazel-bin/hybrid_encryption/hybrid_encryption_cli decrypt private_keyset.bin \
    encrypted_message.bin context_info.txt decrypted_message.txt
```
