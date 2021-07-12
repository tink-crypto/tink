# Tinkey

This utility allows generating and manipulating Tink keysets. It can encrypt or
decrypt keysets with master keys residing in a remote key management service
(KMS). Out of the box it supports AWS KMS and Google Cloud KMS. Adding support
for other KMS is easy, and doesn't require modifying Tinkey.

Tinkey requires Java 8 or later to run.

## Install from prebuilt binaries

Download the latest version of Tinkey from
https://storage.googleapis.com/tinkey/tinkey-1.6.1.tar.gz. This version should
work well on Linux, macOS and Windows.

## Install with Homebrew

```sh
brew tap google/tink https://github.com/google/tink
brew install tinkey
```

## Build from source

-   Install [Bazel](https://docs.bazel.build/versions/master/install.html)

-   Check out the code

```shell
git clone https://github.com/google/tink.git
```

-   Build

```shell
cd tink/tools
bazel build tinkey
```

The binary is located at `bazel-bin/tinkey/tinkey`.

## Usage

`tinkey <command> [<args>]`

Available commands:

*   `add-key`: Generates and adds a new key to a keyset.
*   `convert-keyset`: Changes format, encrypts, decrypts a keyset.
*   `create-keyset`: Creates a new keyset.
*   `create-public-keyset`: Creates a public keyset from a private keyset.
*   `list-key-templates`: Lists all supported key templates.
*   `delete-key`: Deletes a specified key in a keyset.
*   `disable-key`: Disables a specified key in a keyset.
*   `enable-key`: Enables a specified key in a keyset.
*   `list-keyset`: Lists keys in a keyset.
*   `promote-key`: Promotes a specified key to primary.
*   `rotate-keyset`: Performs a key rotation in a keyset.

To obtain info about arguments available/required for a command, run `tinkey
<command>` without further arguments.

-   Generate a keyset, and write it to `private-keyset.cfg`

```shell
tinkey create-keyset --key-template ECDSA_P256 --out private-keyset.cfg
```

-   Add a new key to a keyset

```shell
tinkey add-key --key-template ECDSA_P384 --in private-keyset.cfg \
--out private-keyset.cfg
```

-   Rotate a keyset by adding a primary key

```shell
tinkey rotate-keyset --key-template ED25519 --in private-keyset.cfg \
--out private-keyset.cfg
```

-   List metadata of keys in a keyset:

```shell
tinkey list-keyset --in private-keyset.cfg
```

-   Create a public keyset from a private keyset

```shell
tinkey create-public-keyset --in private-keyset.cfg --out public-keyset.cfg
```

## Work with Key Management System (KMS)

Tinkey can encrypt or decrypt keysets with master keys residing in remote KMSes.
In this mode, users first create a master key in the KMS and tell Tinkey where
the master key is via the `--master-key-uri` option. To create a master key in
Google Cloud KMS, see https://cloud.google.com/kms/docs/quickstart. To create a
master key in AWS KMS, see
http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html.

### Master key URI

Every master key URI starts with a unique prefix that identifies its KMS. The
prefix for AWS KMS is `aws-kms://`, and Google Cloud KMS `gcp-kms://`. AWS KMS
master key URIs are in this format
`aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>`, and Google Cloud KMS
`gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*`.

### Credentials

Tinkey needs credentials to connect to AWS KMS or Google Cloud KMS. Users tell
Tinkey where/how to load credentials via the `--credential` option. If
`--master-key-uri` is specified, `--credential` specifies the credentials file
path. Google Cloud credentials are service account JSON files that can be
created and downloaded from Google Cloud Console. AWS credentials are properties
files with the AWS access key ID is expected to be in the `accessKey` property
and the AWS secret key is expected to be in the `secretKey` property.

If `--credential` is missing Tinkey will attempt to load the default
credentials:

*   AWS KMS:
    http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html#credentials-default

*   Google Clous KMS:
    https://developers.google.com/identity/protocols/application-default-credentials.

### Examples

Please replace
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
in the following examples with appropriate key URIs.

-   Generate a keyset, encrypt, and write it to `encrypted-keyset.cfg`, using
    default credentials

```shell
tinkey create-keyset --key-template AES128_GCM --out encrypted-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
```

-   Generate a keyset, encrypt and write it to `encrypted-keyset.cfg`, using
    credentials in `credentials.json`

```shell
tinkey create-keyset --key-template AES128_GCM --out encrypted-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
--credential credential.json
```

-   List metadata of keys in an encrypted keyset, using credentials in
    `credentials.json`

```shell
tinkey list-keyset --in encrypted-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
--credential credential.json
```

-   Decrypt a keyset, and write the cleartext keyset to `cleartext-keyset.cfg`,
    using default credentials

```shell
tinkey convert-keyset --in encrypted-keyset.cfg --out cleartext-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
```

-   Encrypt a keyset, write the encrypted keyset to `encrypted-keyset.cfg`,
    using default credentials

```shell
tinkey convert-keyset --in cleartext-keyset.cfg --out encrypted-keyset.cfg \
--new-master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
```

-   Add a new key to an encrypted keyset, using default credentials

```shell
tinkey add-key --key-template AES256_GCM --in encrypted-keyset.cfg \
--out encrypted-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
```

-   Rotate an encrypted keyset by adding a primary key

```shell
tinkey rotate-keyset --key-template AES256_GCM --in encrypted-keyset.cfg \
--out encrypted-keyset.cfg \
--master-key-uri gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar
```
