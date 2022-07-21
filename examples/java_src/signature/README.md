# Java digital signature example

This is an example showing how to sign and verify data with Tink using digital
signatures.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
tinkey create-keyset --key-template ECDSA_P256 --out-format JSON \
    --out signature_test_private_keyset.json
tinkey create-public-keyset --in signature_test_private_keyset.json \
    --in-format JSON --out-format JSON --out signature_test_public_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...

echo "some data" > data.txt
touch signature_file.txt

./bazel-bin/signature/signature_example sign \
    ./signature/signature_test_private_keyset.json data.txt signature_file.txt

./bazel-bin/signature/signature_example verify \
    ./signature/signature_test_public_keyset.json data.txt signature_file.txt
```
