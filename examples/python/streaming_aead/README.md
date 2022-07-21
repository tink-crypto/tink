# Python streaming AEAD example

This example shows how to encrypt files with Tink using streaming Authenticated
Encryption with Associated Data (AEAD).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated using Tinkey:

```shell
$ tinkey create-keyset --key-template AES256_CTR_HMAC_SHA256_1MB \
    --out-format JSON --out streaming_aead_keyset.json
```

## Build and run

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/python
$ bazel build ...
```

You can then encrypt a file with:

```shell
$ echo "some data" > testdata.txt

$ ./bazel-bin/streaming_aead/streaming_aead --mode encrypt \
    --keyset_path ./streaming_aead/streaming_aead_keyset.json \
    --input_path testdata.txt \
    --output_path testdata.txt.ciphertext
```

And then decrypt the the output with:

```shell
$ ./bazel-bin/streaming_aead/streaming_aead --mode decrypt \
    --keyset_path ./streaming_aead/streaming_aead_keyset.json \
    --input_path testdata.txt.ciphertext \
    --output_path testdata.txt.plaintext

$ diff testdata.txt testdata.txt.decrypted
```
