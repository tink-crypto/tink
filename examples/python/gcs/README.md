# Python Google Cloud Storage (GCS) client-side encryption example

This example shows how to encrypt/decrypt GCS blobs with Tink using
[Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption).

It shows how you can use Tink to encrypt data with a newly generated *data
encryption key* (DEK) which is wrapped with a KMS key. The data will be
encrypted with AES256 GCM using the DEK and the DEK will be encrypted with the
KMS key and stored alongside the ciphertext in GCS.

The CLI takes the following required arguments:

*   mode: "encrypt" or "decrypt" to indicate if you want to encrypt or decrypt.
*   kek-uri: The URI for the Cloud KMS key to be used for envelope encryption.
*   gcp-credential-file: Name of the file with the Google Cloud Platform (GCP)
    credentials (in JSON format) that can access the Cloud KMS key and the GCS
    input/output blobs.
*   gcp-project-id: The ID of the GCP project hosting the GCS blobs that you
    want to encrypt or decrypt.

When mode is "encrypt", it takes the following additional arguments:

*   local-input-file: Read the plaintext from this local file.
*   gcs-output-blob: Write the encryption result to this blob in GCS. The
    encryption result is bound to the location of this blob. That is, if you
    rename or move it to a different bucket, decryption will fail.

When mode is "decrypt", it takes the following additional arguments:

*   gcs-input-blob: Read the ciphertext from this blob in GCS.
*   local-output-file: Write the decryption result to this local file.

`gcs-input-blob` and `gcs-output-blob` have this format:
`gs://my-bucket-name/my-object-name`.

## Build and Run

### Prequisite

This envelope encryption example uses a Cloud KMS key as a key-encryption key
(KEK). In order to run it, you need to:

*   Create a symmetric key on Cloud KMS. Copy the key URI which is in this
    format:
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>`.

*   Create a bucket on GCS.

*   Create and download a service account that is allowed to encrypt and decrypt
    with the Cloud KMS key, and read/write to the GCS bucket.

### Bazel

```shell
git clone https://github.com/google/tink
cd tink/examples/python
bazel build ...
```

You can then encrypt a file and upload to GCS:

```shell
echo "some data" > testdata.txt
./bazel-bin/gcs/gcs_envelope_aead \
    encrypt \
    gcp-kms://my-cloud-kms-key-uri \
    my-service-account.json \
    my-gcp-project-id \
    testdata.txt gs://my-bucket-name/my-blob-name

```

or download a file from GCS and decrypt it:

```shell
./bazel-bin/gcs/gcs_envelope_aead
    decrypt \
    gcp-kms://my-key-uri \
    my-service-account.json \
    my-gcp-project-id \
    gs://my-bucket-name/my-blob-name testdata.txt.decrypted
```
