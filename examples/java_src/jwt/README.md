# Java JWT signature example

This is an example showing how to sign and verify JSON Web Tokens (JWT) with
Tink.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template JWT_ES256 --out-format JSON \
    --out jwt_test_private_keyset.json
```

## Build and Run

### Bazel

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/java_src
$ bazel build ...
$ touch token.txt

$ ./bazel-bin/jwt/jwt_sign \
    ./jwt/jwt_test_private_keyset.json example_audience token.txt

$ ./bazel-bin/jwt/jwt_generate_public_jwk_set \
    ./jwt/jwt_test_private_keyset.json public_jwk_set.json

$ ./bazel-bin/jwt/jwt_verify \
    public_jwk_set.json example_audience token.txt
```
