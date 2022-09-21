This folder contains GCP credentials that are used for testing Tink.

For security reasons, all credentials in this folder are invalid.

If you want to run tests that depend on them, please create your own
[Cloud KMS key](https://cloud.google.com/kms/docs/creating-keys), and copy the
credentials to `gcp/credential.json` and the key URI to `gcp/key_name.txt`.
