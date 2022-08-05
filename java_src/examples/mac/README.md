# Java MAC example

This example shows how to check the integrity of data with Tink using Message
Authentication Code (MAC).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
tinkey create-keyset --key-template HMAC_SHA256_256BITTAG --out-format JSON \
    --out mac_test_keyset.json
```

## Build and run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...

echo "some data" > data.txt
touch mac_file.txt

./bazel-bin/mac/mac_example compute \
    ./mac/mac_test_keyset.json data.txt mac_file.txt

./bazel-bin/mac/mac_example verify \
    ./mac/mac_test_keyset.json data.txt mac_file.txt
```
