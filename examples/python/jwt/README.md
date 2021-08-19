# Python JWT signature example

This example shows how to generate and verify Json Web Tokens (JWT) with Tink.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template JWT_ES256 --out-format JSON \
    --out jwt_test_private_keyset.json
$ tinkey create-public-keyset --in jwt_test_private_keyset.json \
    --in-format JSON --out-format JSON --out jwt_test_public_keyset.json
```

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

$ ./bazel-bin/jwt/jwt_signature --mode sign \
    --keyset_path ./jwt/jwt_test_private_keyset.json \
    --audience "audience" --token_path token_file.txt
```

Verify a JWT:

```shell
$ ./bazel-bin/jwt/jwt_signature --mode verify \
    --keyset_path ./jwt/jwt_test_public_keyset.json \
    --audience "audience" --token_path token_file.txt
```
