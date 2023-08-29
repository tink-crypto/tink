# Tink

*A multi-language, cross-platform library that provides cryptographic APIs that
are secure, easy to use correctly, and hard(er) to misuse. See also:
https://developers.google.com/tink*.

> **NOTE**: **Tink is moving!**
>
> As part of our roadmap we are splitting Tink into
> [multiple GitHub repositories][split_repo_roadmap_url] that will be hosted at
> [github.com/tink-crypto](https://github.com/tink-crypto) and will be
> independently versioned.
>
> Roughly, we are going to create one repository per language, library extension
> such as KMS (except Tink Python), and tools.
>
> A few important highlights:
>
> -   The migration will be done gradually over the course of 2023 with a new
>     release from each of the new repositories. Releases will be announced in
>     our [mailing list][tink_mailing_list_url].
> -   We will keep updating each implementation/tool in
>     [github.com/google/tink](https://github.com/google/tink) for a specified
>     amount of time; migrated implementations/tools will eventually stop being
>     updated on [github.com/google/tink](https://github.com/google/tink). The
>     support window depends on the specific implementation, as shown in the
>     table below.
> -   New issues and pull requests should be created in the new repos.
>
> Below is the list of resulting repositories, migration timeline and expected
> end of support.
>
> Tink implementation/extension         | New repository                                                                            | Migration status   | End of support in google/tink
> ------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------ | -----------------------------
> Tink Java                             | [tink-crypto/tink-java](https://github.com/tink-crypto/tink-java)                         | Complete (Q1 2023) | Q3 2023
> Tink Java AWS KMS extension           | [tink-crypto/tink-java-awskms](https://github.com/tink-crypto/tink-java-awskms)           | Complete (Q1 2023) | Q3 2023
> Tink Java Google Cloud KMS extension  | [tink-crypto/tink-java-gcpkms](https://github.com/tink-crypto/tink-java-gcpkms)           | Complete (Q1 2023) | Q3 2023
> Tink Java apps extension              | [tink-crypto/tink-java-apps](https://github.com/tink-crypto/tink-java-apps)               | Complete (Q1 2023) | Q3 2023
> Tink Tinkey                           | [tink-crypto/tink-tinkey](https://github.com/tink-crypto/tink-tinkey)                     | Complete (Q2 2023) | Q4 2023
> Tink C++                              | [tink-crypto/tink-cc](https://github.com/tink-crypto/tink-cc)                             | Complete (Q2 2023) | Q2 2024
> Tink C++ AWS KMS extension            | [tink-crypto/tink-cc-awskms](https://github.com/tink-crypto/tink-cc-awskms)               | Complete (Q2 2023) | Q2 2024
> Tink C++ Google Cloud KMS extension   | [tink-crypto/tink-cc-gcpkms](https://github.com/tink-crypto/tink-cc-gcpkms)               | Complete (Q2 2023) | Q2 2024
> Tink Go                               | [tink-crypto/tink-go](https://github.com/tink-crypto/tink-go)                             | Complete (Q3 2023) | Q1 2024
> Tink Go AWS KMS extension             | [tink-crypto/tink-go-awskms](https://github.com/tink-crypto/tink-go-awskms)               | Complete (Q3 2023) | Q1 2024
> Tink Go Google Cloud KMS extension    | [tink-crypto/tink-go-gcpkms](https://github.com/tink-crypto/tink-go-gcpkms)               | Complete (Q3 2023) | Q1 2024
> Tink Go HashiCorp Vault KMS extension | [tink-crypto/tink-go-hcvault](https://github.com/tink-crypto/tink-go-hcvault)             | Complete (Q3 2023) | Q1 2024
> Tink Python                           | [tink-crypto/tink-py](https://github.com/tink-crypto/tink-py)                             | Complete (Q3 2023) | Q1 2024
> Tink Obj-C                            | [tink-crypto/tink-objc](https://github.com/tink-crypto/tink-objc)                         | Complete (Q3 2023) | Q1 2024
> Tink cross language tests             | [tink-crypto/tink-cross-lang-tests](https://github.com/tink-crypto/tink-cross-lang-tests) | Complete (Q3 2023) | N/A

> **NOTE**: **We are removing Tink for JavaScript/TypeScript**
>
> We are removing the Tink JavaScript/TypeScript library from our current Github
> repository (master branch). As part of our effort to migrate Tink to
> https://github.com/tink-crypto, we will not release an individual
> JavaScript/Typescript repository. Furthermore, the JavaScript/TypeScript
> [directory](https://github.com/google/tink/tree/master/javascript) in the
> current release branch (v1.7.0) will no longer be actively supported.
>
> _We aim to remove the JS/TS directory from the current Tink Github repository
> (master branch) on **June 22, 2023**. We will also deprecate the Tink npm
> package on this date._
>
> See [this](https://github.com/google/tink/issues/689) tracking issue for more
> details.
>
> Feel free to use our [mailing list][tink_mailing_list_url] to raise any
> questions, issues or concerns.

[split_repo_roadmap_url]: https://developers.google.com/tink/roadmap#splitting_tink_into_multiple_github_repositories
[tink_mailing_list_url]: https://groups.google.com/forum/#!forum/tink-users

## Index

1.  [Introduction](#introduction)
2.  [Current status](#current-status)
3.  [Getting started](#getting-started)
4.  [Learn more](#learn-more)
5.  [Contact and mailing list](#contact-and-mailing-list)
6.  [Maintainers](#maintainers)

## Introduction

Using crypto in your application [shouldn't have to][devs_are_users_too_slides]
feel like juggling chainsaws in the dark. Tink is a crypto library written by a
group of cryptographers and security engineers at Google. It was born out of our
extensive experience working with Google's product teams,
[fixing weaknesses in implementations](https://github.com/google/wycheproof),
and providing simple APIs that can be used safely without needing a crypto
background.

Tink provides secure APIs that are easy to use correctly and hard(er) to misuse.
It reduces common crypto pitfalls with user-centered design, careful
implementation and code reviews, and extensive testing. At Google, Tink is one
of the standard crypto libraries, and has been deployed in hundreds of products
and systems.

To get a quick overview of Tink design please take a look at
[slides][tink_talk_slides] from [a talk about Tink][tink_talk_recording]
presented at [Real World Crypto 2019](https://rwc.iacr.org/2019/).

[devs_are_users_too_slides]: https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf
[tink_talk_slides]: docs/Tink-a_cryptographic_library--RealWorldCrypto2019.pdf
[tink_talk_recording]: https://www.youtube.com/watch?v=pqev9r3rUJs&t=9665

## Current status

[Java/Android](docs/JAVA-HOWTO.md), [C++](docs/CPP-HOWTO.md),
[Obj-C](docs/OBJC-HOWTO.md), [Go](docs/GOLANG-HOWTO.md), and
[Python](docs/PYTHON-HOWTO.md) are field tested and ready for production. The
latest version is [1.7.0](https://github.com/google/tink/releases/tag/v1.7.0),
released on 2022-08-09.

Javascript/Typescript is in an alpha state and should only be used for testing.
Please see the intent to remove statement
[here](https://github.com/google/tink/issues/689).

**`Ubuntu`**                        | **`macOS`**
----------------------------------- | ---------------------------------
[![Kokoro Ubuntu][ubuntu_badge]](#) | [![Kokoro macOS][macos_badge]](#)

[ubuntu_badge]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png
[macos_badge]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png

## Getting started

Documentation for the project is located at https://developers.google.com/tink.
Currently, it details a variety of common usage scenarios and covers the Java
and Python implementations. The site will be populated with more content over
time.

Alternatively, you can look at all of the [`examples`] which demonstrate
performing simple tasks using Tink in a variety of languages.

[`examples`]: https://github.com/google/tink/tree/master/examples

*   Python

```sh
pip3 install tink
```

*   Golang

```sh
go get github.com/google/tink/go/...
```

*   Java

```xml
<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>tink</artifactId>
  <version>1.7.0</version>
</dependency>
```

*   Android

```
dependencies {
  implementation 'com.google.crypto.tink:tink-android:1.7.0'
}
```

*   Objective-C/iOS

```sh
cd /path/to/your/Xcode project/
pod init
pod 'Tink', '1.7.0'
pod install
```

## Learn more

*   [Java HOW-TO](docs/JAVA-HOWTO.md)
*   [C++ HOW-TO](docs/CPP-HOWTO.md)
*   [Obj-C HOW-TO](docs/OBJC-HOWTO.md)
*   [Go HOW-TO](docs/GOLANG-HOWTO.md)
*   [Python HOW-TO](docs/PYTHON-HOWTO.md)
*   [Security and Usability Design Goals](docs/SECURITY-USABILITY.md)
*   [Supported Crypto Primitives](docs/PRIMITIVES.md)
*   [Key Management](docs/KEY-MANAGEMENT.md)
*   [Managing keys with Tinkey](docs/TINKEY.md)
*   [Known Issues](docs/KNOWN-ISSUES.md)

## Community-driven ports

Out of the box Tink supports a wide range of languages, but it still doesn't
support every language. Fortunately, some users like Tink so much that they've
ported it to their favorite languages! Below you can find notable ports.

**WARNING** While we usually review these ports, until further notice, we do not
maintain them and have no plan to support them in the foreseeable future.

*   [Clojure](https://github.com/perkss/tinklj)

## Contact and mailing list

If you want to contribute, please read [CONTRIBUTING](docs/CONTRIBUTING.md) and
send us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major product
updates, you may want to subscribe to our [mailing list][tink_mailing_list_url].

## Maintainers

Tink is maintained by (A-Z):

-   Moreno Ambrosin
-   Taymon Beal
-   Daniel Bleichenbacher
-   William Conner
-   Thai Duong
-   Thomas Holenstein
-   Stefan Kölbl
-   Charles Lee
-   Cindy Lin
-   Fernando Lobato Meeser
-   Atul Luykx
-   Rafael Misoczki
-   Sophie Schmieg
-   Laurent Simon
-   Elizaveta Tretiakova
-   Jürg Wullschleger

Alumni:

-   Haris Andrianakis
-   Tanuj Dhir
-   Quan Nguyen
-   Bartosz Przydatek
-   Enzo Puig
-   Veronika Slívová
-   Paula Vidas
-   Cathie Yun
-   Federico Zalcberg
