# Python example: working with encrypted keysets

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
cd tink/examples/python
bazel build ...
```

You can generate an encrypted keyset:

```shell
# Replace `<my-key-uri>` in `gcp-kms://<my-key-uri>` with your key URI, and
# my-service-account.json with your service account's credential JSON file.
./bazel-bin/encrypted_keyset/encrypted_keyset generate \
    aes128_gcm_test_encrypted_keyset.json \
    gcp-kms://<my-key-uri> \
    my-service-account.json
```

You can then encrypt a file:

```shell
echo "some data" > testdata.txt
./bazel-bin/encrypted_keyset/encrypted_keyset encrypt \
    aes128_gcm_test_encrypted_keyset.json \
    gcp-kms://<my-key-uri> \
    my-service-account.json \
    testdata.txt testdata.txt.encrypted
```

or decrypt the file with:

```shell
./bazel-bin/encrypted_keyset/encrypted_keyset decrypt \
    gcp-kms://<my-key-uri> \
    my-service-account.json \
    testdata.txt.encrypted testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
