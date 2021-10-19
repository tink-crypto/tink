# Python JWT signature example

This example shows how to generate and verify Json Web Tokens (JWT) with Tink.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template JWT_ES256 --out-format JSON \
    --out jwt_test_private_keyset.json
```

Note that the private key here uses Tink's JSON keyset format, which is
different and not compatible with JSON Web Key set (JWK set) format.

## Build and run

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/python
$ bazel build ...
```

Generate a JWT:

```shell
$ touch token_file.txt

$ ./bazel-bin/jwt/jwt_sign \
    --keyset_path ./jwt/jwt_test_private_keyset.json \
    --audience "audience" --token_path token_file.txt
```

Generate the public keyset in
[JWK Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) format:

```shell
$ touch public_jwk_set.json

$ ./bazel-bin/jwt/jwt_generate_public_jwk_set \
    --keyset_path ./jwt/jwt_test_private_keyset.json \
    --public_jwk_set_path public_jwk_set.json
```

Verify a token:

```shell
$ ./bazel-bin/jwt/jwt_verify \
    --public_jwk_set_path public_jwk_set.json \
    --audience "audience" --token_path token_file.txt
```
