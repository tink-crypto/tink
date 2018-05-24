# C++ Hello World

This is a command-line tool that can encrypt and decrypt small files using _authenticated
encryption with associated data_ ([AEAD](https://github.com/google/tink/blob/master/doc/PRIMITIVES.md#authenticated-encryption-with-associated-data)).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

Moreoever, since this app shares the same Bazel's WORKSPACE with Tink, its
BUILD file can directly depend on Tink.


## Build and run

**Bazel**

```shell
git clone https://github.com/google/tink
cd tink
bazel build ...
echo "some plaintext" > foo.txt
./bazel-bin/examples/helloworld/cc/hello_world ./examples/helloworld/cc/aes128_gcm_test_keyset_json.txt\
    encrypt foo.txt "some aad" bar.encrypted
./bazel-bin/examples/helloworld/cc/hello_world ./examples/helloworld/cc/aes128_gcm_test_keyset_json.txt\
    decrypt bar.encrypted "some aad" foo-decrypted.txt
cat foo2.txt
```

TODO: copy this app to
[tink-examples](https://github.com/thaidn/tink-examples/tree/master/helloworld/)
and add instructions on how to build it there.
