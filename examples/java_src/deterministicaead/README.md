# Java Deterministic AEAD example

This example shows how to encrypt files with Tink using Deterministic
Authenticated Encryption with Associated Data (Deterministic AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
tinkey create-keyset --key-template AES256_SIV --out-format JSON \
    --out deterministic_aead_test_keyset.json
```

## Build and run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

Encrypt a file:

```shell
echo "some data" > testdata.txt

./bazel-bin/deterministicaead/deterministic_aead_example encrypt \
    ./deterministicaead/deterministic_aead_test_keyset.json \
    testdata.txt testdata.txt.encrypted
```

Decrypt a file:

```shell
./bazel-bin/deterministicaead/deterministic_aead_example decrypt \
    ./deterministicaead/deterministic_aead_test_keyset.json \
    testdata.txt.encrypted testdata.txt.decrypted

diff testdata.txt testdata.txt.decrypted
```
