# Python MAC example

This example shows how to check the integrity of data using Message
Authentication Code (MAC).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template HMAC_SHA256_256BITTAG --out-format JSON \
    --out mac_test_keyset.json
```

## Build and Run

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/python/examples
$ bazel build ...
```

Compute a MAC:

```shell
$ echo "some data" > data.txt
$ touch mac_file.txt
$ ./bazel-bin/mac/mac --mode compute \
    --keyset_path ./mac/mac_test_keyset.json \
    --data_path data.txt --mac_path mac_file.txt
```

Verify a MAC:

```shell
$ ./bazel-bin/mac/mac --mode verify \
    --keyset_path ./mac/mac_test_keyset.json \
    --data_path data.txt --mac_path mac_file.txt
```
