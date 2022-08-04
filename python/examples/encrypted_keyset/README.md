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

*   Create service account that is allowed to encrypt and decrypt with the above
    key and download a JSON credentials file.

### Bazel

```shell
$ git clone https://github.com/google/tink
$ cd tink/python/examples
$ bazel build ...
```

You can generate an encrypted keyset:

```shell
# Replace `<my-key-uri>` in `gcp-kms://<my-key-uri>` with your key URI, and
# my-service-account.json with your service account's credential JSON file.
$ ./bazel-bin/encrypted_keyset/encrypted_keyset --mode generate \
    --keyset_path aes128_gcm_test_encrypted_keyset.json \
    --kek_uri gcp-kms://<my-key-uri> \
    --gcp_credential_path my-service-account.json
```

You can then encrypt a file:

```shell
$ echo "some data" > testdata.txt
$ ./bazel-bin/encrypted_keyset/encrypted_keyset --mode encrypt \
    --keyset_path aes128_gcm_test_encrypted_keyset.json \
    --kek_uri gcp-kms://<my-key-uri> \
    --gcp_credential_path my-service-account.json \
    --input_path testdata.txt --output_path testdata.txt.encrypted
```

Or decrypt the file with:

```shell
$ ./bazel-bin/encrypted_keyset/encrypted_keyset --mode decrypt \
    --keyset_path aes128_gcm_test_encrypted_keyset.json \
    --kek_uri gcp-kms://<my-key-uri> \
    --gcp_credential_path my-service-account.json \
    --input_path testdata.txt.encrypted --output_path testdata.txt.decrypted
$ diff testdata.txt testdata.txt.decrypted
```
