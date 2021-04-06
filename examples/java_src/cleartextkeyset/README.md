# Java example: working with cleartext keysets

This example shows how to generate or load a cleartext keyset, obtain a
primitive, and use the primitive to do crypto.

WARNING: this is not recommended, consider protecting your keysets with a key
management system.

## Build and run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

You can generate a cleartext keyset:

```shell
./bazel-bin/cleartextkeyset/cleartext_keyset_example generate aes128_gcm_test_keyset.json
```

You can then encrypt a file with the resulting keyset:

```shell
echo "some data" > testdata.txt
./bazel-bin/cleartextkeyset/cleartext_keyset_example encrypt \
    aes128_gcm_test_keyset.json \
    testdata.txt testdata.txt.encrypted
```

or decrypt the file with:

```shell
./bazel-bin/cleartextkeyset/cleartext_keyset_example decrypt \
    aes128_gcm_test_keyset.json \
    testdata.txt.encrypted testdata.txt.decrypted

diff testdata.txt testdata.txt.decrypted
```
