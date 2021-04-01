# Python MAC example

This example shows how to check the integrity of data using Message
Authentication Code (MAC).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
tinkey create-keyset --key-template HMAC_SHA256_256BITTAG --out-format JSON \
--out mac_test_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
echo "some data" > data.txt

git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
echo "some data" > data.txt
touch mac_file.txt

./bazel-bin/mac/mac compute \
    ./mac/mac_test_keyset.json data.txt mac_file.txt
./bazel-bin/mac/mac verify \
    ./mac/mac_test_keyset.json data.txt mac_file.txt
```
