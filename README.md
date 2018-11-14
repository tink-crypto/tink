# Tink

**`Ubuntu`**                                                                                   | **`macOS`**
---------------------------------------------------------------------------------------------- | -----------
[![Kokoro Ubuntu](https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png)](#) | [![Kokoro macOS](https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png)](#)

## Introduction

Using crypto in your application [shouldn't have
to](https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf)
feel like juggling chainsaws in the dark. Tink is a crypto library written by a
group of cryptographers and security engineers at Google. It was born out of
our extensive experience working with Google's product teams, [fixing
weaknesses in implementations](https://github.com/google/wycheproof), and
providing simple APIs that can be used safely without needing a crypto
background.

Tink provides secure APIs that are easy to use correctly and hard(er) to misuse.
It reduces common crypto pitfalls with user-centered design, careful
implementation and code reviews, and extensive testing. At Google, Tink is
already being used to secure data of many products such as AdMob, Google Pay,
Google Assistant, Firebase, the Android Search App, etc.

## Getting started

**TIP** The easiest way to get started with Tink is to install
[Bazel](https://docs.bazel.build/versions/master/install.html), then build, run
and play with the [`hello world
examples`](https://github.com/google/tink/tree/master/examples/helloworld).

Tink performs cryptographic tasks via so-called [primitives](docs/PRIMITIVES.md),
each of which is defined via a corresponding interface that specifies the
functionality of the primitive. For example, _symmetric key encryption_ is
offered via an [_AEAD-primitive_ (Authenticated Encryption with Associated
Data)](docs/PRIMITIVES.md#authenticated-encryption-with-associated-data), that
supports two operations:

*   `encrypt(plaintext, associated_data)`, which encrypts the given `plaintext`
    (using `associated_data` as additional AEAD-input) and returns the resulting
    ciphertext
*   `decrypt(ciphertext, associated_data)`, which decrypts the given
    `ciphertext` (using `associated_data` as additional AEAD-input) and returns
    the resulting plaintext

Before implementations of primitives can be used, they must be registered at
runtime with Tink, so that Tink "knows" the desired implementations. Here's how
you can register all implementations of all primitives in Tink:

```java
    import com.google.crypto.tink.config.TinkConfig;

    TinkConfig.register();
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
    import com.google.crypto.tink.aead.AeadKeyTemplates;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        AeadKeyTemplates.AES128_GCM);

    // 2. Get the primitive.
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    // 3. Use the primitive.
    byte[] ciphertext = aead.encrypt(plaintext, associatedData);
```

## Current Status

*   [Java and Android](docs/JAVA-HOWTO.md), [C++](docs/CPP-HOWTO.md) and
    [Obj-C](docs/OBJC-HOWTO.md) are field tested and ready for production. The
    latest version is
    [1.2.1](https://github.com/google/tink/releases/tag/v1.2.1), released on
    2018-11-15.

*   Tink for Go and JavaScript are in active development.

## Learn More

*   [Java HOW-TO](docs/JAVA-HOWTO.md)
*   [C++ HOW-TO](docs/CPP-HOWTO.md)
*   [Obj-C HOW-TO](docs/OBJC-HOWTO.md)
*   [Security and Usability Design Goals](docs/SECURITY-USABILITY.md)
*   [Supported Crypto Primitives](docs/PRIMITIVES.md)
*   [Key Management](docs/KEY-MANAGEMENT.md)
*   [Tinkey](docs/TINKEY.md)
*   [Known Issues](docs/KNOWN-ISSUES.md)
*   [Feature Roadmap](docs/ROADMAP.md)
*   [Java Hacking Guide](docs/JAVA-HACKING.md)

## Contact and mailing list

If you want to contribute, please read [CONTRIBUTING](docs/CONTRIBUTING.md)
and send us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major product
updates, you may want to subscribe to our [mailing
list](https://groups.google.com/forum/#!forum/tink-users). To join, simply send
an empty email to tink-users+subscribe@googlegroups.com.

## Maintainers

Tink is maintained by (A-Z):

-   Haris Andrianakis
-   Daniel Bleichenbacher
-   Thai Duong
-   Thomas Holenstein
-   Charles Lee
-   Quan Nguyen
-   Bartosz Przydatek
-   Veronika Slívová
