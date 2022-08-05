# Java encrypted keysets example

This example shows how to generate or load an encrypted keyset, obtain a
primitive, and use the primitive to do crypto.

## Build and run

### Prequisite

This example uses a Cloud KMS key as a key-encryption key (KEK) to
encrypt/decrypt a keyset, which in turn is used to encrypt files.

In order to run this example, you need to:

*   Create a symmetric key on Cloud KMs. Copy the key URI which is in this
    format:
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>`.

*   Create and download a service account that is allowed to encrypt and decrypt
    with the above key.

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/java_src
bazel build ...
```

Generate an encrypted keyset:

```shell
# Replace `<my-key-uri>` in `gcp-kms://<my-key-uri>` with your key URI, and
# my-service-account.json with your service account's credential JSON file.
./bazel-bin/encryptedkeyset/encrypted_keyset_example \
    generate \
    aes128_gcm_test_encrypted_keyset.json \
    gcp-kms://<my-key-uri> \
    my-service-account.json
```

Encrypt a file:

```shell
echo "some data" > testdata.txt

./bazel-bin/encryptedkeyset/encrypted_keyset_example \
    encrypt \
    aes128_gcm_test_encrypted_keyset.json \
    gcp-kms://<my-key-uri> \
    my-service-account.json \
    testdata.txt testdata.txt.encrypted
```

Decrypt a file:

```shell
./bazel-bin/encryptedkeyset/encrypted_keyset_example \
    decrypt \
    aes128_gcm_test_encrypted_keyset.json \
    gcp-kms://<my-key-uri> \
    my-service-account.json \
    testdata.txt.encrypted testdata.txt.decrypted

diff testdata.txt testdata.txt.decrypted
```
