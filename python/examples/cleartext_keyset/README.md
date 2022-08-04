# Python example: working with cleartext keysets

This example shows how to generate or load a cleartext keyset, obtain a
primitive, and use the primitive to do crypto.

WARNING: this is not recommended, consider protecting your keysets with a key
management system.

## Build and run

### Bazel

```shell
$ git clone https://github.com/google/tink
$ cd tink/python/examples
$ bazel build ...
```

You can generate a cleartext keyset:

```shell
$ ./bazel-bin/cleartext_keyset/cleartext_keyset --mode generate \
    --keyset_path aes128_gcm_test_keyset.json
```

You can then encrypt a file with the resulting keyset:

```shell
$ echo "some data" > testdata.txt
$ ./bazel-bin/cleartext_keyset/cleartext_keyset --mode encrypt \
    --keyset_path aes128_gcm_test_keyset.json \
    --input_path testdata.txt --output_path testdata.txt.encrypted
```

Or decrypt a file with:

```shell
$ ./bazel-bin/cleartext_keyset/cleartext_keyset --mode decrypt \
    --keyset_path aes128_gcm_test_keyset.json \
    --input_path testdata.txt.encrypted --output_path testdata.txt.decrypted

$ diff testdata.txt testdata.txt.decrypted
```
