# Java hybrid encryption example

This example shows how to encrypt data with Tink using hybrid encryption.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
tinkey create-keyset \
    --key-template DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM \
    --out-format JSON --out hybrid_test_private_keyset.json

tinkey create-public-keyset --in hybrid_test_private_keyset.json \
    --in-format JSON --out-format JSON --out hybrid_test_public_keyset.json
```

## Build and run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

You can then encrypt a file:

```shell
echo "some data" > testdata.txt
./bazel-bin/hybrid/hybrid_example encrypt \
    hybrid_test_public_keyset.json testdata.txt testdata.txt.encrypted
```

or decrypt the file:

```shell
./bazel-bin/hybrid/hybrid_example decrypt \
    hybrid_test_private_keyset.json testdata.txt.encrypted \
    testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
