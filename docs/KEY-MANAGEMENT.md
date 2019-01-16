# Key Management with Tink

In addition to cryptographic operations Tink provides support for key management
features like key versioning, key rotation, and storing keysets or encrypting
with master keys in remote key management systems (KMS).  To get a quick
overview of Tink design, incl. key management features, you can also take a look
at [slides](Tink-a_cryptographic_library--RealWorldCrypto2019.pdf) from [a talk
about Tink](https://www.youtube.com/watch?v=pqev9r3rUJs&t=9665) presented at
[Real World Crypto 2019](https://rwc.iacr.org/2019/).

[Tinkey](TINKEY.md) is a command-line tool that allows managing Tink's key
material. Tink also provides a rich key management API (e.g., see
[KeysetManager](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KeysetManager.java)).

## Key, Keyset, and KeysetHandle

Tink performs cryptographic tasks via so-called [primitives](PRIMITIVES.md),
each of which is defined via a corresponding interface that specifies the
functionality of the primitive.

A particular implementation of a _primitive_ is identified by a cryptographic
**key** structure that contains all key material and parameters needed to
provide the functionality of the primitive. The key structure is a _protocol
buffer_, whose globally unique name (a.k.a. _type url_) is referred to as **key
type**, and is used as an identifier of the corresponding implementation of a
primitive. Any particular implementation comes in a form of a **KeyManager**
which “understands” the key type: the manager can instantiate the primitive
corresponding to a given key, or can generate new keys of the supported key
type.

To take advantage of key rotation and other key management features, a Tink user
works usually not with single keys, but with **keysets**, which are just sets of
keys with some additional parameters and metadata. In particular, this extra
information in the keyset determines which key is _primary_ (i.e. will be used
to create new cryptographic data like ciphertexts, or signatures), which keys
are _enabled_ (i.e. can be used to process existing cryptographic data, like
decrypt ciphertext or verify signatures), and which keys should not be used any
more. For more details about the structure of keys, keysets and related protocol
buffers see
[tink.proto](https://github.com/google/tink/blob/master/proto/tink.proto).

The keys in a keyset can belong to _different implementations/key types_, but
must all implement the _same primitive_. Any given keyset (and any given key)
can be used for one primitive only. Moreover, to protect from accidental leakage
or corruption, an Tink user doesn’t work _directly_ with keysets, but rather
with **KeysetHandle** objects, which form a wrapper around the keysets. Creation
of KeysetHandle objects can be restricted to specific factories (whose
visibility can be governed by a white list), to enable control over actual
storage of the keys and keysets, and so avoid accidental leakage of secret key
material.

## Key Management Systems

Tink/Tinkey can encrypt or decrypt keysets with master keys residing in remote
KMSes. Currently, the following KMSes are supported:

-   Google Cloud KMS
-   Amazon KMS
-   Android Keystore
-   Apple iOS KeyChain (planned)

You can easily add support for in-house key management systems, without having
to change anything in Tink/Tinkey. For example, when Tink/Tinkey is deployed at
Google, it supports encrypting keysets with master keys stored in our internal
key management system.

To encrypt Tink's key material with master keys in KMSes, you first create a
master key in the KMS and tell Tink/Tinkey where the master key is by providing
a master key URI.

KMS              | Format of master key URIs
---------------- | ----------------------------------------------------------
AWS KMS          | `aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>`
GCP KMS          | `gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*`
Android Keystore | `android-keystore://*`

Every master key URI starts with a unique prefix that identifies its KMS. The
prefix for AWS KMS is `aws-kms://`, Google Cloud KMS `gcp-kms://`, and Android
Keystore `android-keystore://`.

To create master keys:

-   In Google Cloud KMS: https://cloud.google.com/kms/docs/quickstart.

-   In Amazon KMS:
    http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html.

-   In Android Keystore:
    https://developer.android.com/training/articles/keystore.html.

### Credentials

Tink/Tinkey needs credentials to connect to AWS KMS or Google Cloud KMS. Google
Cloud credentials are service account JSON files that can be created and
downloaded from Google Cloud Console. AWS credentials are properties files with
the AWS access key ID is expected to be in the `accessKey` property and the AWS
secret key is expected to be in the `secretKey` property.

Tink/Tinkey can also load the default credentials:

*   AWS KMS:
    http://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html#credentials-default

*   Google Cloud KMS:
    https://developers.google.com/identity/protocols/application-default-credentials.
