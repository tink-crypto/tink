This folder contains AWS and GCP credentials that are used for testing Tink.

# AWS

For security reasons, all AWS credentials in this folder are invalid. If you
want to run tests that depend on them, please create your own
[AWS access keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html).
The credentials are required in several formats expected by different APIs. For
example, Java expects the credentials as a
[properties file](https://docs.aws.amazon.com/AmazonS3/latest/dev/AuthUsingAcctOrUserCredentials.html).
In order to cover all tests across all languages you will have to replace
`aws_credentials_cc.txt`, `credentials_aws.cred`, `credentials_aws.csv` and
`credentials_aws.ini`. These can be generated in a similar way to this [script](https://github.com/google/tink/blob/master/kokoro/copy_credentials.sh).

# GCP

For security reasons, all GCP credentials in this folder are invalid. If you
want to run tests that depend on them, please create your own
[Cloud KMS key](https://cloud.google.com/kms/docs/creating-keys), and copy the
credentials to `credential.json` and the key URI to `gcp_key_name.txt`.
