# Python Deterministic AEAD example

This example shows how to encrypt files with Tink using Deterministic
Authenticated Encryption with Associated Data (Deterministic AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
$ tinkey create-keyset --key-template AES256_SIV --out-format JSON \
    --out deterministic_aead_test_keyset.json
```

## Build and run

### Bazel

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/python
$ bazel build ...
```

You can then encrypt a file

```shell
$ echo "some data" > testdata.txt
$ ./bazel-bin/deterministic_aead/deterministic_aead --mode encrypt \
    --keyset_path deterministic_aead/deterministic_aead_test_keyset.json \
    --input_path testdata.txt --output_path testdata.txt.encrypted
```

or decrypt the file with

```shell
$ ./bazel-bin/deterministic_aead/deterministic_aead --mode decrypt \
    --keyset_path deterministic_aead/deterministic_aead_test_keyset.json \
    --input_path testdata.txt.encrypted --output_path testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
