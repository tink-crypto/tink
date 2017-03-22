# Tink

Tink is a small cryptographic library that provides a safe, simple, agile and
fast way to accomplish some common cryptographic tasks. It is written by a
group of cryptographers and security engineers at Google, but it is not an
official Google product.

## Getting started

TODO

## Why Tink?

We wrote this section so that you have a better idea of what Tink provides and
why we designed it this way. We’ve had a lot of joys working on Tink, and we
want to share with you what we’ve learned. We hope that you’d enjoy using
Tink, as much as we’ve enjoyed working on it!

### Features

Tink provides a set of basic tools to perform common crypto tasks in a variety
of environments.

Currently Tink supports the 4 fundamental crypto operations including
authenticated encryption with associated data (AEAD), message authentication
code (MAC), digital signature (PublicKeySign and PublicKeyVerify), and hybrid
encryption (HybridEncrypt and HybridDecrypt). In the future we might add other
primitives such as deterministic encryption (e.g., SIV modes), pseudorandom
function (e.g., HMAC as a PRF), strong pseudorandom permutation (e.g., HEH).

Tink also supports
[envelope](http://docs.aws.amazon.com/kms/latest/developerguide/workflow.html)
[encryption](https://cloud.google.com/kms/docs/data-encryption-keys) which is
getting popular with Cloud users. In this mode, Cloud users generate a data
encryption key (DEK) locally, encrypt data with DEK, send DEK to a KMS such as
AWS KMS or Google Cloud KMS to be encrypted, and stores encrypted DEK with
encrypted data; at a later point Cloud users can retrieve encrypted data and DEK,
use the KMS to decrypt DEK, and use decrypted DEK to decrypt the data.


#### Primitives

The following AEAD algorithms are supported:

- AES-EAX
- AES-GCM
- AES-CTR-HMAC-AEAD
- CHACHA20-POLY1305 (planned)

The following MAC algorithms are supported:

- HMAC-SHA2

The following digital signature algorithms are supported:

- ECDSA over NIST curves
- EdDSA over Ed25519 (planned)

The following hybrid encryption algorithms are supported:

- ECIES with AEAD and HKDF, based on [Victor Shoup's ISO 18033-2 design]
(http://www.shoup.net/iso/).
- NaCl CryptoBox (planned)

#### Key Management

Key management is one of the most important aspects in any cryptosystem, but
it is also the most overlooked. Tink provides out of box support for storing
and loading keys from key management systems, and deliberately makes it hard
to resort to dangerous practices such as hard-coding keys in source code.

Tink supports the following key management systems:

- Google Cloud KMS
- Amazon KMS
- Android Keystore System (planned)
- Apple iOS KeyChain (planned)

You can easily add support for in-house key management system, without having
to change anything in Tink.

#### Languages

Tink for Java is field tested and ready for production. C++ is in active
development and support for Go, Python, Javascript is in planning.

For each language there is a pure implementation in that language and a native
one for users that want better performance.

#### Platforms

Tink supports Android, Linux (Google Cloud Engine or Amazon EC2), Google App
Engine. iOS support is in active development.

### Security

Tink reduces common crypto pitfalls with user-centered design, careful
implementation and code reviews, and extensive testing.

Tink stems from combined decades of experience in building and breaking
real-world cryptosystems. We are also maintainers of
[Project Wycheproof](https://github.com/google/wycheproof), a framework for
validating the correctness of crypto libraries, thus Tink has been
continuously tested and should be safe against known crypto weaknesses.

### Safety

Tink provides APIs that decrease the potential for abuse or misuse.

In particular, implementations of a high level interface are foolproof in the
sense: We assume that the attacker has complete freedom in calling methods of
a high level interface; under this assumption the security is not compromised.

For example if the underlying encryption mode requires nonces and is insecure
if nonces are reused then the interface do not allow to pass nonces. We also
assume that the attacker can get access to memory passed into a method, even
if a cryptographic operation (e.g. decryption) failed.

Tink's interfaces abstract away from the underlying implementation. Instances
are usable without knowing the underlying class that implements it. It is also
possible to change the underlying implementation of an interface without
changes to the call of the interface. Interfaces have security guarantees that
must be satisfied by each primitive implementing the interface.

A good practice is to use each key for one purpose only. The storage format of
Tink keys contains information such that correct usage of the key can be
checked at runtime.

### Simplicity

Tink provides APIs that are simple and easy to use.

You can accomplish common crypto operations such as data encryption, digital
signatures, etc. with only a few lines of code. For example, to encrypt a
piece of data using authenticated encryption you need only 3 lines of code:

```
// 1. Read a keyset from some storage system
KeysetHandle keysetHandle = ...

// 2. Get an instance of the Aead primitive.
Aead aead = AeadFactory.getPrimitive(keysetHandle);

// 3. Use the primitive.
byte[] ciphertext = aead.encrypt(plaintext, associatedData);
```

### Composability

The core of Tink is less than 2000 lines of code.

All other components are recombinant that can be selected and assembled in
various combinations to satisfy specific user requirements about code size or
performance. For example, if you need only digital signatures, you don't have
to include authenticated encryption. This design allowed us to satisfy an
early user that needed a hybrid encryption library that, after compiled and
optimized, must be smaller than 5KB.

### Extensibility

It is easy to add new primitives, protocols or interfaces to Tink.

Without touching the core library, you can easily add support for new
algorithms, new ciphertext formats, or new key management systems (e.g.,
in-house Hardware Security Modules), etc.

Interfaces for primitives typically have strong security guarantees and
frequently restrict parameter choices. This may exclude some encryption modes.
Rather than adding them to existing interfaces and weakening the guarantees of
the interface it is possible to add new interfaces and describe the security
guarantees appropriately.

### Agility

Tink provides out of box support for key rotation, deprecation of obsolete
schemes and adaptation of new ones. Once a crypto primitive is found broken,
you can switch to a new primitive by rotating the key without changing or
recompiling code. The library is also very versatile. No part of it is hard to
replace.

### Interoperability

Tink produces and consumes ciphertexts that are compatible with other
libraries.

Except in a few cases, implementations of crypto primitives in Tink come from
existing libraries such as OpenSSL, BoringSSL, NaCl, Bouncy Castle, OpenJDK,
etc. Because Tink is not a rewrite of these underlying libraries, but is
rather a high-level abstraction of them, it supports ciphertext formats and
algorithms supported by these libraries.

### Readability

Tink shows crypto properties (i.e., whether safe against chosen-ciphertext
attacks) right in the interfaces, allowing security auditors and automated
tools quickly discovering incorrect usages.

On an abstract level we think that it is not necessary to know whether the
cryptosystem has been proposed by Rivest, Shamir and Adleman or by Victor
Shoup, but you should be able to determine if an object implements an
encryption or signature algorithm. Also, knowing that an encryption mode is
authenticated is more important than knowing it uses AES. This is why we name
our interfaces as generic as possible (e.g., Aead, PublicKeySign, etc.), but
not too general (e.g., Crypter, Signer, etc.)

### Visibility

Tink provides standalone static types for potential dangerous operations
(e.g., loading cleartext keys from disk), allowing restricting, monitoring and
logging their usages.

## Maintainers

Tink is maintained by:

- Daniel Bleichenbacher
- Thai Duong
- Quan Nguyen
- Bartosz Przydatek

## Contact and mailing list

If you want to contribute, please read CONTRIBUTING and send us pull requests.
You can also report bugs or request new tests.

If you'd like to talk to our developers or get notified about major new tests,
you may want to subscribe to our
[mailing list](https://groups.google.com/forum/#!forum/tink-users). To join,
simply send an empty email to tink-users+subscribe@googlegroups.com.
