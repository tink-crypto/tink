# Tink

*A multi-language, cross-platform library that provides cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.*

https://developers.google.com/tink

**`Ubuntu`**                        | **`macOS`**
----------------------------------- | ---------------------------------
[![Kokoro Ubuntu][ubuntu_badge]](#) | [![Kokoro macOS][macos_badge]](#)

[ubuntu_badge]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-ubuntu.png
[macos_badge]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-macos.png

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
extensive experience working with Google's product teams, [fixing weaknesses in
implementations](https://github.com/google/wycheproof), and providing simple
APIs that can be used safely without needing a crypto background.

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

If you want to contribute, please read [CONTRIBUTING](docs/CONTRIBUTING.md)
and send us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major product
updates, you may want to subscribe to our
[mailing list](https://groups.google.com/forum/#!forum/tink-users).

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
