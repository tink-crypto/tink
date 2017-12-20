# Tink

**`Ubuntu`**                                                                              | **`macOS`**
----------------------------------------------------------------------------------------- | -----------
![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png) | ![Kokoro macOS](https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png)

## Introduction

Tink is a cryptographic library. The design goals are:

*   **Simplicity** Tink provides APIs that are simple and easy to use
    correctly.  Most cryptographic operations such as data encryption, digital
    signatures, etc.  can be done with only a few lines of code.

*   **Security** Tink reduces common cryptographic pitfalls with user-centered
    design, careful implementation and code reviews, and extensive testing.

*   **Misuse-proof** Tink assumes that the attacker has complete freedom in
    calling methods of a high level interface; under this assumption the
    security is not compromised. For example, if the underlying encryption mode
    requires nonces and is insecure if nonces are reused then the interface does
    not allow to pass nonces.

*   **Extensibility** Tink makes it easy to support new primitives, new algorithms, new
    ciphertext formats, new key management systems, etc.

*   **Agility** Tink provides built-in cryptographic agility. It supports key
    rotation, deprecation of obsolete schemes and adaptation of new ones. For example, if an
    implementation of a cryptographic primitive is found broken, you can switch
    to a different implementation by rotating keys, without changing or recompiling code.

*   **Interoperability** Tink produces and consumes ciphertexts that are
    compatible with existing cryptographic libraries. Tink supports encrypting
    or storing keys in Amazon KMS, Google Cloud KMS, Android Keystore, and it is
    easy to support other key management systems.

*   **Versatility** No part of Tink is hard to replace or remove. All components
    are recombinant, and can be selected and assembled in various combinations.
    For example, if you need only digital signatures, you can exclude symmetric
    key encryption components.

*   **Readability** Tink shows cryptographic properties (i.e., whether safe
    against chosen-ciphertext attacks) right in the interfaces, allowing
    security auditors and automated tools quickly discovering incorrect usages.
    Tink provides standalone static types for potential dangerous operations
    (e.g., loading cleartext keys from disk), allowing discovering, restricting,
    monitoring and logging their usages.

Tink is written by a group of cryptographers and security engineers at Google,
but it is **not an official Google product**. In particular, it is not meant as
a replacement or successor of [Keyczar](https://github.com/google/keyczar).

**Current Status**

* [Tink for Java](doc/JAVA-HOWTO.md) is field tested and ready for production --
  it is used in several Google products such as AdMob, Android Pay, and Google
  Android Search App.

* [Tink for C++](doc/CPP-HOWTO.md) is catching up with
  [Tink for Java](doc/JAVA-HOWTO.md) in terms of features and stability,
  and the offered functionality is 100%-compatible with Java
  (cf. [cross-language tests](tools/testing/cross_language/).
  We plan to make a first C++ release soon.

* Tink for Obj-C and Go are in active development.

## Getting started

**TIP** The easiest way to get started with Tink is to install
[Bazel](https://docs.bazel.build/versions/master/install.html), then build, run
and study the [`hello world samples`](https://github.com/google/tink/tree/master/examples/helloworld).

Tink performs cryptographic tasks via so-called [primitives](doc/PRIMITIVES.md),
each of which is defined via a corresponding interface that specifies the
functionality of the primitive. For example, _symmetric key encryption_ is
offered via an [_AEAD-primitive_ (Authenticated Encryption with Associated
Data)](doc/PRIMITIVES.md#authenticated-encryption-with-associated-data), that
supports two operations:

*   `encrypt(plaintext, associated_data)`, which encrypts the given `plaintext`
    (using `associated_data` as additional AEAD-input) and returns the resulting
    ciphertext
*   `decrypt(ciphertext, associated_data)`, which decrypts the given
    `ciphertext` (using `associated_data` as additional AEAD-input) and returns
    the resulting plaintext

Before implementations of primitives can be used, they must be registered at
runtime with Tink, so that Tink "knows" the desired implementations. Here's how
you can register all implementations of all primitives in Tink for Java 1.0.0:

```java
    import com.google.crypto.tink.Config;
    import com.google.crypto.tink.config.TinkConfig;

    Config.register(TinkConfig.TINK_1_0_0);
```

After implementations of primitives have been registered, the basic use of Tink
proceeds in three steps:

1.  Load or generate the cryptographic key material (a `Keyset` in Tink terms).
2.  Use the key material to get an instance of the chosen primitive.
3.  Use that primitive to accomplish the cryptographic task.

Here is how these steps would look like when encrypting or decrypting with an
AEAD primitive in Java:

```java
    import com.google.crypto.tink.Aead;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.aead.AeadFactory;
    import com.google.crypto.tink.aead.AeadKeyTemplates;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.AES128_GCM);

    // 2. Get the primitive.
    Aead aead = AeadFactory.getPrimitive(keysetHandle);

    // 3. Use the primitive.
    byte[] ciphertext = aead.encrypt(plaintext, aad);
```

See the [Java HOWTO](doc/JAVA-HOWTO.md#obtaining-and-using-a-primitive) for how
to obtain and use other primitives.

## Important Warnings

Do not use APIs including fields and methods marked with the `@Alpha`
annotation.  They can be modified in any way, or even removed, at any time. They
are in the package, but not for official, production release, but only for
testing.

## Learn More

*   [Tink Primitives](doc/PRIMITIVES.md)
*   [Key Management](doc/KEY-MANAGEMENT.md)
*   [Java HOW-TO](doc/JAVA-HOWTO.md)
*   [C++ HOW-TO](doc/CPP-HOWTO.md)
*   [Tinkey](doc/TINKEY.md)

## Contact and mailing list

If you want to contribute, please read
[CONTRIBUTING](https://github.com/google/tink/blob/master/CONTRIBUTING.md) and
send us pull requests. You can also report bugs or request new tests.

If you'd like to talk to our developers or get notified about major new tests,
you may want to subscribe to our [mailing
list](https://groups.google.com/forum/#!forum/tink-users). To join, simply send
an empty email to tink-users+subscribe@googlegroups.com.

## Maintainers

Tink is maintained by:

-   Daniel Bleichenbacher
-   Thai Duong
-   Quan Nguyen
-   Bartosz Przydatek
