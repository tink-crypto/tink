# C++ Hello World

This is a command-line tool that can encrypt and decrypt small files using [AEAD
(Authenticated Encryption with Associated
Data)](../../../docs/PRIMITIVES.md#authenticated-encryption-with-associated-data).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

Moreover, since this app shares the same Bazel WORKSPACE with Tink, its BUILD
file can directly depend on Tink.

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink
bazel build ...
echo "some plaintext" > foo.txt
./bazel-bin/examples/helloworld/cc/hello_world ./examples/helloworld/cc/aes128_gcm_test_keyset_json.txt\
    encrypt foo.txt "some aad" bar.encrypted
./bazel-bin/examples/helloworld/cc/hello_world ./examples/helloworld/cc/aes128_gcm_test_keyset_json.txt\
    decrypt bar.encrypted "some aad" foo-decrypted.txt
cat foo-decrypted.txt
```

TODO: copy this app to
[tink-examples](https://github.com/thaidn/tink-examples/tree/master/helloworld/)
and add instructions on how to build it there.
