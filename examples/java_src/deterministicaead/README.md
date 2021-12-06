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

You can then encrypt a file

```shell
_key_file_path="./deterministic_aead_test_keyset.json"
echo "some data" > testdata.txt
./bazel-bin/deterministicaead/deterministic_aead_example encrypt \
    "${_key_file_path}" testdata.txt testdata.txt.encrypted
```

or decrypt the file with

```shell
./bazel-bin/deterministicaead/deterministic_aead_example decrypt \
    "${_key_file_path}" testdata.txt.encrypted testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
