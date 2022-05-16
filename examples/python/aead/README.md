# Python AEAD example

This example shows how to encrypt files with Tink using Authenticated Encryption
with Associated Data (AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
$ tinkey create-keyset --key-template AES128_GCM --out-format JSON \
    --out aead_test_keyset.json
```

## Build and Run

### Bazel

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/python
$ bazel build ...
```

You can then encrypt a file with:

```shell
$ echo "some data" > testdata.txt
$ ./bazel-bin/aead/aead --mode encrypt \
    --keyset_path ./aead/aead_test_keyset.json \
    --input_path testdata.txt --output_path testdata.txt.encrypted
```

and then decrypt the the output with:

```shell
$ ./bazel-bin/aead/aead --mode decrypt \
    --keyset_path ./aead/aead_test_keyset.json \
    --input_path testdata.txt.encrypted --output_path testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
