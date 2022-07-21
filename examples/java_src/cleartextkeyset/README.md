# Java cleartext keysets example

This example shows how to generate or load a cleartext keyset, obtain a
primitive, and use the primitive to do crypto.

WARNING: This is not recommended, consider protecting your keysets with a key
management system.

## Build and run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

Generate a cleartext keyset:

```shell
./bazel-bin/cleartextkeyset/cleartext_keyset_example generate aes128_gcm_test_keyset.json
```

Encrypt a file with the resulting keyset:

```shell
echo "some data" > testdata.txt
./bazel-bin/cleartextkeyset/cleartext_keyset_example encrypt \
    aes128_gcm_test_keyset.json \
    testdata.txt testdata.txt.encrypted
```

Decrypt the file with the resulting keyset:

```shell
./bazel-bin/cleartextkeyset/cleartext_keyset_example decrypt \
    aes128_gcm_test_keyset.json \
    testdata.txt.encrypted testdata.txt.decrypted

diff testdata.txt testdata.txt.decrypted
```
