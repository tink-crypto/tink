# Python Google Cloud Storage (GCS) client-side encryption example

This example shows how to encrypt/decrypt GCS blobs with Tink using
[Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption).

It shows how you can use Tink to encrypt data with a newly generated *data
encryption key* (DEK) which is wrapped with a KMS key. The data will be
encrypted with AES256 GCM using the DEK and the DEK will be encrypted with the
KMS key and stored alongside the ciphertext in GCS.

The CLI takes the following required arguments:

*   `--mode`: Either `encrypt` or `decrypt` to indicate if you want to encrypt
    or decrypt.
*   `--kek_uri`: The URI for the Cloud KMS key to be used for envelope encryption.
*   `--gcp_credential_path`: Name of the file with the Google Cloud Platform (GCP)
    credentials (in JSON format) that can access the Cloud KMS key and the GCS
    input/output blobs.
*   `--gcp_project_id`: The ID of the GCP project hosting the GCS blobs that you
    want to encrypt or decrypt.
*   `--local_path`:
    *   When `--mode encrypt`, read the plaintext from this local file.
    *   When `--mode decrypt`, write the decryption result to this local file.
*   `--gcs_blob_path`:
    *   Format: `gs://my-bucket-name/my-object-name`
    *   When `--mode encrypt`, write the encryption result to this blob in GCS.
        The encryption result is bound to the location of this blob. That is, if
        you rename or move it to a different bucket, decryption will fail.
    *   When `--mode decrypt`, read the ciphertext from this blob in GCS.

## Build and run

### Prequisite

This envelope encryption example uses a Cloud KMS key as a key-encryption key
(KEK). In order to run it, you need to:

*   Create a symmetric key on Cloud KMS. Copy the key URI which is in this
    format:
    `projects/<my-project>/locations/global/keyRings/<my-key-ring>/cryptoKeys/<my-key>`

*   Create a bucket on GCS.

*   Create a service account that is allowed to encrypt and decrypt with the
    Cloud KMS key, and read/write to the GCS bucket. Then download the JSON
    credentials file.

### Bazel

Build the examples:

```shell
$ git clone https://github.com/google/tink
$ cd tink/python/examples
$ bazel build ...
```

You can then encrypt a file and upload the result to GCS:

```shell
$ echo "some data" > testdata.txt
$ ./bazel-bin/gcs/gcs_envelope_aead \
    --mode encrypt \
    --kek_uri gcp-kms://my-cloud-kms-key-uri \
    --gcp_credential_path my-service-account.json \
    --gcp_project_id my-gcp-project-id \
    --local_path testdata.txt \
    --gcs_blob_path gs://my-bucket-name/my-blob-name
```

Or download a file from GCS and decrypt it:

```shell
$ ./bazel-bin/gcs/gcs_envelope_aead
    --mode decrypt \
    --kek_uri gcp-kms://my-key-uri \
    --gcp_credential_path my-service-account.json \
    --gcp_project_id my-gcp-project-id \
    --gcs_blob_path gs://my-bucket-name/my-blob-name \
    --local_path testdata.txt.decrypted
```
