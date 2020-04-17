# Python File MAC

This is a command-line tool that can check the integrity of a file using
[MAC (Message Authentication Code)](../../../docs/PRIMITIVES.md#message-authentication-code).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

Moreover, since this app shares the same Bazel WORKSPACE with Tink, its BUILD
file can directly depend on Tink.

The key material was generated with:

```shell
tinkey create-keyset --key-template HMAC_SHA256_256BITTAG --out-format JSON \
--out tmp/hmac_sha256_256bittag_test_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
echo "some data" > data.txt
echo "01293ce6590fb883aa111a53e56d537dea5641b664901e35ce10e0c31df8398218fa9b030d" > expected.txt

./bazel-bin/file_mac/file_mac_cleartext ./examples/python/file_mac/hmac_sha256_256bittag_test_keyset.json \
    data.txt
./bazel-bin/file_mac/file_mac_cleartext ./examples/python/file_mac/hmac_sha256_256bittag_test_keyset.json \
    data.txt expected.txt
```
