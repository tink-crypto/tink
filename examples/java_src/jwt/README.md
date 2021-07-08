# Java JWT signature example

This is an example showing how to sign and verify JSON Web Tokens (JWT) with
Tink.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
tinkey create-keyset --key-template JWT_ES256 --out-format JSON \
    --out jwt_test_private_keyset.json
tinkey create-public-keyset --in jwt_test_private_keyset.json \
    --in-format JSON --out-format JSON --out jwt_test_public_keyset.json
```

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
touch token_file.txt

./bazel-bin/jwt/jwt_signature_example sign \
    ./signature/jwt_test_private_keyset.json testSubject token_file.txt
./bazel-bin/jwt_/jwt_signature_example verify \
    ./signature/jwt_test_public_keyset.json testSubject token_file.txt
```
