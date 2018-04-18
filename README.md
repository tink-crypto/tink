# Tink

**`Ubuntu`**                                                                              | **`macOS`**
----------------------------------------------------------------------------------------- | -----------
![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png) | ![Kokoro macOS](https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png)

## Introduction

Using crypto in your application [shouldn't have
to](https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf)
feel like juggling chainsaws in the dark. Tink is a crypto library written by a
group of cryptographers and security engineers at Google. It was born out of
our extensive experience working with Google's product teams, [fixing
weaknesses in implementations](https://github.com/google/wycheproof), and
providing simple APIs that can be used safely without needing a crypto
background.

Tink provides secure APIs that are easy to use correctly. It reduces common
crypto pitfalls with user-centered design, careful implementation and code
reviews, and extensive testing. You can add features like encryption, decryption
and signing to your application with Tink - the same library AdMob, Google Pay,
the Android Search App and several Google products also use to secure their
applications.

## Getting started

**TIP** The easiest way to get started with Tink is to install
[Bazel](https://docs.bazel.build/versions/master/install.html), then build, run
and play with the [`hello world
examples`](https://github.com/google/tink/tree/master/examples/helloworld).

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
you can register all implementations of all primitives in Tink for Java 1.1.0:

```java
    import com.google.crypto.tink.Config;
    import com.google.crypto.tink.config.TinkConfig;

    Config.register(TinkConfig.TINK_1_1_0);
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

## Current Status

*   [Tink for Java and Android](doc/JAVA-HOWTO.md) are field tested and ready
    for production. Latest version is
    [1.1.0](https://github.com/google/tink/releases/tag/v1.1.0), released on
    04/18/2018.

*   [Tink for C++](doc/CPP-HOWTO.md) and [Tink for Obj-C](doc/OBJC-HOWTO.md)
    are catching up with [Tink for Java](doc/JAVA-HOWTO.md) in terms of
    features and stability, and the offered functionality is 100%-compatible
    with Java (cf. [cross-language tests](tools/testing/cross_language/). We
    plan to make a first release in June 2018.

*   Tink for Go is in active development.

*   Tink for Javascript and C# are in planning.

## Learn More

*   [Java HOW-TO](doc/JAVA-HOWTO.md)
*   [C++ HOW-TO](doc/CPP-HOWTO.md)
*   [Security and Usability Design Goals](doc/SECURITY-USABILITY.md)
*   [Supported Crypto Primitives](doc/PRIMITIVES.md)
*   [Key Management](doc/KEY-MANAGEMENT.md)
*   [Tinkey](doc/TINKEY.md)
*   [Known Issues](doc/KNOWN-ISSUES.md)
*   [Feature Roadmap](doc/ROADMAP.md)
*   [Java Hacking Guide](doc/JAVA-HACKING.md)

## Contact and mailing list

If you want to contribute, please read [CONTRIBUTING](CONTRIBUTING.md) and send
us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major new tests,
you may want to subscribe to our [mailing
list](https://groups.google.com/forum/#!forum/tink-users). To join, simply send
an empty email to tink-users+subscribe@googlegroups.com.

## Maintainers

Tink is maintained by:

-   Daniel Bleichenbacher
-   Thai Duong
-   Quan Nguyen
-   Bartosz Przydatek
