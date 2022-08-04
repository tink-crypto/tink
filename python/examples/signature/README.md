# Python digital signature example

This example shows how to sign and verify data with Tink using digital
signatures.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template ECDSA_P256 --out-format JSON \
    --out signature_test_private_keyset.json
$ tinkey create-public-keyset --in signature_test_private_keyset.json \
    --in-format JSON --out-format JSON --out signature_test_public_keyset.json
```

## Build and run

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/python/examples
$ bazel build ...
```

Generate a signature:

```shell
$ echo "some data" > data.txt
$ touch signature_file.txt

$ ./bazel-bin/signature/signature --mode sign \
    --keyset_path ./signature/signature_test_private_keyset.json \
    --data_path data.txt --signature_path signature_file.txt
```

Verify a signature:

```shell
$ ./bazel-bin/signature/signature --mode verify \
    --keyset_path ./signature/signature_test_public_keyset.json \
    --data_path data.txt --signature_path signature_file.txt
```
