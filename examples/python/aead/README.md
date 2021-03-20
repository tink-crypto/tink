# Python Envelope Encryption

This is a command-line tool that can encrypt files using
[Authenticated Encryption with Associated Data](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_\(AEAD\))

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with Tinkey:

```shell
tinkey create-keyset --key-template AES128_GCM --out-format JSON \
    --out aes128_gcm_test_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
```

You can then encrypt a file

```shell
echo "some data" > testdata.txt
./bazel-bin/aead/aead encrypt testdata.txt testdata.txt.encrypted
```

or decrypt the file with

```shell
./bazel-bin/aead/aead decrypt testdata.txt.encrypted testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
