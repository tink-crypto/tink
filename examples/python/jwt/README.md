# Python JWT signature example

This example shows how to generate and verify Json Web Tokens (JWT) with Tink.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

The key material was generated with:

```shell
$ tinkey create-keyset --key-template JWT_ES256 --out-format JSON \
    --out jwt_test_private_keyset.json

$ tinkey create-public-keyset --in jwt_test_private_keyset.json \
  --in-format JSON --out jwt_test_public_keyset.json --out-format JSON
```

Note that these keysets use Tink's JSON keyset format, which is different and
not compatible with JSON Web Key set (JWK set) format.

## Build and run

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/examples/python
$ bazel build ...
```

Generate a JWT token using the private keyset:

```shell
$ touch token_file.txt

$ ./bazel-bin/jwt/jwt_sign \
    --private_keyset_path ./jwt/jwt_test_private_keyset.json \
    --audience "audience" --token_path token_file.txt
```

Verify the token using the public keyset:

```shell
$ ./bazel-bin/jwt/jwt_verify \
    --public_keyset_path public_jwk_set.json \
    --audience "audience" --token_path token_file.txt
```

You can also convert the public keyset into
[JWK Set](https://datatracker.ietf.org/doc/html/rfc7517#section-5) format. This
is useful if you want to share the public keyset with someone who is not using
Tink. Note that this functionality was added after the release v1.6.1.

```shell
$ touch public_jwk_set.json

$ ./bazel-bin/jwt/jwt_generate_public_jwk_set \
    --public_keyset_path ./jwt/jwt_test_private_keyset.json \
    --public_jwk_set_path public_jwk_set.json
```

You can also verify a token using a public keyset given in JWK Set format:

```shell
$ ./bazel-bin/jwt/jwt_verify \
    --public_jwk_set_path public_jwk_set.json \
    --audience "audience" --token_path token_file.txt
```
