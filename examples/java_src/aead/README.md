# Java AEAD example

This example shows how to encrypt data with Tink using Authenticated Encryption
with Associated Data (AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
tinkey create-keyset --key-template AES128_GCM --out-format JSON \
    --out aead_test_keyset.json
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
./bazel-bin/aead/aead_example encrypt testdata.txt testdata.txt.encrypted
```

or decrypt the file:

```shell
./bazel-bin/aead/aead_example decrypt testdata.txt.encrypted testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
