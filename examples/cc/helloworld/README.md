# C++ Hello World

This is a command-line tool that can encrypt and decrypt small files using [AEAD
(Authenticated Encryption with Associated
Data)](../../../docs/PRIMITIVES.md#authenticated-encryption-with-associated-data).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

## Build and Run

### Bazel

```shell
# Build the code.
git clone https://github.com/google/tink
cd tink/examples/cc
bazel build ...

# Create some input.
echo "some plaintext" > foo.txt

# Encrypt.
./bazel-bin/helloworld/hello_world ./helloworld/aes128_gcm_test_keyset_json.txt \
    encrypt foo.txt "some aad" foo.encrypted

# Decrypt.
./bazel-bin/helloworld/hello_world ./helloworld/aes128_gcm_test_keyset_json.txt \
    decrypt foo.encrypted "some aad" foo-decrypted.txt

# Inspect the output.
cat foo-decrypted.txt
```
