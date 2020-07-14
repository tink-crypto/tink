# Known Issues in Tink

This doc lists known issues in Tink. Please report new issues by opening new
tickets or emailing the maintainers at `tink-users@googlegroups.com`.

## C++

*   Before 1.4.0, AES-CTR-HMAC-AEAD keys and the
    [EncryptThenAuthenticate](https://github.com/google/tink/blob/master/cc/subtle/encrypt_then_authenticate.cc)
    subtle implementation may be vulnerable to chosen-ciphertext attacks. An
    attacker can generate ciphertexts that bypass the HMAC verification if and
    only if all of the following conditions are true:

    -   Tink C++ is used on systems where `size_t` is a 32-bit integer. This is
        usually the case on 32-bit machines.
    -   The attacker can specify long (>= 2^29 bytes ~ 536MB) associated data.

    This issue was reported by Quan Nguyen of Snap security team.

## Java

*   Tink supports Java 8 or newer. Java 7 support was removed since 1.4.0.

*   Tink is built on top of Java security providers, but, via
    [Project Wycheproof](https://github.com/google/wycheproof), we found many
    security issues in popular providers. Tink provides countermeasures for most
    problems, and we've also helped upstream fix many issues. Still, there are
    some issues in old providers that we cannot fix. We recommend use Tink with
    the latest version of Conscrypt, Oracle JDK, OpenJDK or Bouncy Castle. If
    you cannot use the latest version, you might want to avoid using ECDSA
    (alternative: ED25519) or AES-GCM (alternatives: AES-EAX or
    AES-CTR-HMAC-AEAD).

## Android

*   The minimum API level that Tink supports is 19 (Android KitKat). This covers
    more than 90% of all Android phones. Tink hasn't been tested on older
    versions. It might or might not work. Drop us a line if you really need to
    support ancient Android phones.

*   On Android Marshmallow (API level 23) or older, the
    `newSeekableDecryptingChannel` method in implementations of `StreamingAead`
    doesn't work. It depends on
    [SeekableByteChannel](https://developer.android.com/reference/java/nio/channels/SeekableByteChannel.html),
    which is only available on API level 24 or newer. Users should use
    `newEncryptingStream` instead.

*   On Android Lollipop (API level 21) or older, `AndroidKeysetManager` does not
    support wrapping keysets with Android Keystore, but it'd store keysets in
    cleartext in private preference. This is secure enough for most
    applications.

*   On Android KitKat (API level 19) without [Google Play
    Services](https://developers.google.com/android/guides/overview), `AES-GCM`
    does not work properly because KitKat uses Bouncy Castle 1.48 which doesn't
    support updateAAD. If Google Play Services is present, `AES-GCM` should work
    well. If you want to support all Android versions, without depending on
    Google Play Services, please use `CHACHA20-POLY1305`, `AES-EAX`, or
    `AES-CTR-HMAC-AEAD`.

## Signature malleability

*   ECDSA signatures are malleable. You probably can ignore this issue, unless
    you're working on Bitcoin or cryptocurrencies and have to worry about
    [transaction
    malleability](https://en.bitcoin.it/wiki/Transaction_malleability). In that
    case you want to use ED25519 signatures which are non-malleable.

## Envelope encryption - Benign malleability

*   Envelope encryption uses a third-party provider (e.g. GCP, AWS) to encrypt
    the *data encryption key (DEK)*. It is possible to modify certain parts of
    the *encrypted DEK* without detection when using *KmsEnvelopeAead* with
    *AwsKmsAead* or *GcpKmsAead* as the remote provider. This is due to some
    metadata being included (for instance version numbers) which is not
    authenticated and modifications are not detected by the provider. Note that
    this violates the CCA2 property for this interface, although the ciphertext
    will still decrypt to the correct DEK. When using this interface one should
    not rely on that for each DEK there only exists a single *encrypted DEK*.

## Streaming AEAD - potential integer overflow issues

*   Streaming AEAD implementations encrypt the plaintext in segments. Tink uses
    a 4-byte segment counter. When encrypting a stream consisting of more than
    2^32 segments, the segment counter might overflow and lead to leakage of key
    material or plaintext. This problem was found in the Java and Go
    implementations of the AES-GCM-HKDF-Streaming key type, and has been fixed
    since 1.4.0.
