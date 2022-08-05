# Java Streaming AEAD example

This example shows how to encrypt files with Tink using Streaming Authenticated
Encryption with Associated Data (Streaming AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
tinkey create-keyset --key-template AES128_GCM_HKDF_4KB --out-format JSON \
    --out streaming_aead_test_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

Encrypt a file:

```shell
echo "some data" > testdata.txt
./bazel-bin/streamingaead/streamingaead_example encrypt \
    ./streamingaead/streaming_aead_test_keyset.json \
    testdata.txt testdata.txt.encrypted
```

Decrypt a file:

```shell
./bazel-bin/streamingaead/streamingaead_example decrypt \
    ./streamingaead/streaming_aead_test_keyset.json \
    testdata.txt.encrypted testdata.txt.decrypted

diff testdata.txt testdata.txt.decrypted
```
