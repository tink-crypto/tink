This folder contains AWS and GCP credentials that are used for testing Tink.

# AWS

The AWS credentials in this folder are used to access only a single test key.
Access is also limited to where source IP address is from Google.

The credentials are provided in several formats expected by different APIs. For
example, Java expects the credentials as a
[properties file](https://docs.aws.amazon.com/AmazonS3/latest/dev/AuthUsingAcctOrUserCredentials.html).

# GCP

For security reasons, all GCP credentials in this folder are invalid. If you
want to run tests that depend on them, please create your own
[Cloud KMS key](https://cloud.google.com/kms/docs/creating-keys), and copy the
credentials to `credential.json` and the key URI to `gcp_key_name.txt`.
