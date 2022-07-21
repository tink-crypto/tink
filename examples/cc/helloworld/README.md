# C++ Hello World

This is a command-line tool that can encrypt and decrypt small files using
[AEAD (Authenticated Encryption with Associated Data)](https://developers.google.com/tink/aead).

It demonstrates the basic steps of using Tink, namely loading key material,
obtaining a primitive, and using the primitive to do crypto.

## Build and Run

### Bazel

```shell
# Build the code.
git clone https://github.com/google/tink
cd tink/examples/cc
bazel build ...

# Create some input.
echo "some plaintext" > foo.txt

# Encrypt.
./bazel-bin/helloworld/hello_world \
  ./helloworld/aes128_gcm_test_keyset_json.txt \
  encrypt \
  foo.txt \
  "some aad" \
  foo.encrypted

# Decrypt.
./bazel-bin/helloworld/hello_world \
  ./helloworld/aes128_gcm_test_keyset_json.txt \
  decrypt \
  foo.encrypted \
  "some aad" \
  foo-decrypted.tx

# Inspect the output.
cat foo-decrypted.txt
```

### CMake

```shell

# Clone the Tink repository.
git clone https://github.com/google/tink
cd tink/examples/cc/helloworld

# Build the hello world example.
(
  mkdir build && cd build
  # Note: Specify -DTINK_USE_SYSTEM_OPENSSL=ON if you want to build Tink against
  # OpenSSL rather than BoringSSL. CMake will search for a suitable OpenSSL
  # library in the system's library path.
  cmake .. -DCMAKE_CXX_STANDARD=11
  make -j"$(nproc)"
)

# Create some input.
echo "some plaintext" > foo.txt

./build/hello_world \
  aes128_gcm_test_keyset_json.txt \
  encrypt \
  foo.txt \
  "some aad" \
  foo.txt.encrypted

./build/hello_world \
  aes128_gcm_test_keyset_json.txt \
  decrypt \
  foo.txt.encrypted \
  "some aad" \
  foo.txt.decrypted

if [[ "$(diff foo.txt foo.txt.decrypted)" == "" ]]; then
  echo "File correctly encrypted and decrypted"
else
  echo "Failed to encrypt-and-decrypt. Diff:"
  diff foo.txt foo.txt.decrypted
fi
```

The `cmake_build_test.sh` script will run an encrypt-then-decrypt test with
AEAD. You can build Tink against OpenSSL by passing the `--openssl` option --
the script will download, build and install OpenSSL in a temporary directory.
