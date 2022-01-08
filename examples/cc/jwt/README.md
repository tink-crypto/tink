# C++ Digital Signatures CLI

This is a command-line utility for generating JSON Web Token (JWT) keys, and
creating and verifying JWTs.

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

## Build and Run

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/cc
bazel build ...
./bazel-bin/jwt/jwt_signature_cli gen-private-key private_keyset.bin
./bazel-bin/jwt/jwt_signature_cli get-public-key private_keyset.bin \
    public_keyset.bin
./bazel-bin/jwt/jwt_signature_cli sign private_keyset.bin \
    my-audience token.txt
./bazel-bin/jwt/jwt_signature_cli verify public_keyset.bin \
    my-audience token.txt result.txt
cat result.txt
```
