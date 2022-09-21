This folder contains AWS credentials that are used for testing Tink.

For security reasons, all credentials in this folder are invalid. If you want to
run tests that depend on them, please create your own [AWS access
keys][aws-access-keys].

The credentials are required in several formats expected by different APIs. For
example, Java expects the credentials as a [properties file][properties-file].
In order to cover all tests across all languages you have to replace
`aws/credentials.cred`, `aws/credentials.csv` and `aws/credentials.ini`. These
can be generated in a similar way to this [credential copying
script][copy-credentials-script].

[aws-access-keys]: https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
[properties-file]: https://docs.aws.amazon.com/AmazonS3/latest/dev/AuthUsingAcctOrUserCredentials.html
[copy-credentials-script]: https://github.com/google/tink/blob/master/kokoro/copy_credentials.sh
