# Tink Primitives

[Tink](https://github.com/google/tink) performs cryptographic tasks via
so-called _primitives_, which provide an abstract representation of the provided
functionality. Tink primitives encompass the following cryptographic operations
and are supported via the corresponding interfaces:

| **Primitive**                                       | **Interfaces**                 |
| --------------------------------------------------- | ------------------------------ |
| Authenticated Encryption with Associated Data (AEAD)| AEAD                           |
| *Streaming* AEAD                                    | StreamingAEAD                  |
| *Deterministic* AEAD                                | DeterministicAEAD              |
| Message Authentication Code (MAC)                   | MAC                            |
| Pseudo Random Function Family (PRF)                 | Prf, PrfSet                    |
| Hybrid encryption                                   | HybridEncrypt, HybridDecrypt   |
| Digital signatures                                  | PublicKeySign, PublicKeyVerify |

The interface names above correspond with the Java implementation. Other
language implementations may have modified interface names due to differing
naming conventions.

The tables in the section below summarize the current implementations of
primitives available in the corresponding languages, and the subsequent sections
describe the main properties of Tink primitives.

## Supported primitives and their implementations

### Primitives supported by language

**Primitive**      | **Java** | **C++** | **Objective-C** | **Go** | **Python**
------------------ | :------: | :-----: | :-------------: | :----: | :--------:
AEAD               | yes      | yes     | yes             | yes    | yes
Streaming AEAD     | yes      | yes     | **no**          | yes    | yes
Deterministic AEAD | yes      | yes     | yes             | yes    | yes
MAC                | yes      | yes     | yes             | yes    | yes
PRF                | yes      | yes     | **no**          | yes    | yes
Digital signatures | yes      | yes     | yes             | yes    | yes
Hybrid encryption  | yes      | yes     | yes             | yes    | yes

JavaScript is currently under development.

### Primitive implementations supported by language

| **Primitive**      | **Implementation**                | **Java** | **C++ (BoringSSL)** | **C++ (OpenSSL)** | **Objective-C** | **Go**     | **Python** |
| ------------------ | --------------------------------- | :------: | :-----------------: | :---------------: | :-------------: | :--------: | :--------: |
| AEAD               | AES-GCM                           | yes      | yes                 | yes               | yes             | yes        | yes        |
|                    | AES-GCM-SIV                       | yes      | yes                 | **no**            | **no**          | **no**     | **no**     |
|                    | AES-CTR-HMAC                      | yes      | yes                 | yes               | yes             | yes        | yes        |
|                    | AES-EAX                           | yes      | yes                 | yes               | yes             | **no**     | yes        |
|                    | KMS Envelope                      | yes      | yes                 | yes               | **no**          | yes        | yes        |
|                    | CHACHA20-POLY1305                 | yes      | **no**              | **no**            | **no**          | yes        | **no**     |
|                    | XCHACHA-POLY1305                  | yes      | yes                 | **no**            | yes             | yes        | yes        |
| Streaming AEAD     | AES-GCM-HKDF-STREAMING            | yes      | yes                 | yes               | **no**          | yes        | yes        |
|                    | AES-CTR-HMAC-STREAMING            | yes      | yes                 | yes               | **no**          | yes        | yes        |
| Deterministic AEAD | AES-SIV                           | yes      | yes                 | yes               | yes             | yes        | yes        |
| MAC                | HMAC-SHA2                         | yes      | yes                 | yes               | yes             | yes        | yes        |
|                    | AES-CMAC                          | yes      | yes                 | yes               | yes             | yes        | yes        |
| PRF                | HKDF-SHA2                         | yes      | yes                 | yes               | **no**          | yes        | yes        |
|                    | HMAC-SHA2                         | yes      | yes                 | yes               | **no**          | yes        | yes        |
|                    | AES-CMAC                          | yes      | yes                 | yes               | **no**          | yes        | yes        |
| Digital Signatures | ECDSA over NIST curves            | yes      | yes                 | yes (*)           | yes             | yes        | yes        |
|                    | Ed25519                           | yes      | yes                 | yes               | yes             | yes        | yes        |
|                    | RSA-SSA-PKCS1                     | yes      | yes                 | yes               | yes             | **no**     | yes        |
|                    | RSA-SSA-PSS                       | yes      | yes                 | yes               | yes             | **no**     | yes        |
| Hybrid Encryption  | ECIES with AEAD                   | yes      | yes                 | yes               | yes             | yes        | yes        |
|                    | ECIES with DeterministicAEAD      | yes      | yes                 | yes               | **no**          | yes        | yes        |
|                    | HKDF                              | yes      | yes                 | yes               | yes             | yes        | yes        |

(*) EC key creation from seed (`DeriveKey`) is unsupported.

## General properties of all primitives

- stateless (hence thread-safe)
- copy-safe (for the parameters)
- at least 128-bit security (with an exception for RSA)

## Authenticated Encryption with Associated Data

AEAD primitive (Authenticated Encryption with Associated Data) provides
functionality of symmetric authenticated encryption. Implementations of this
primitive are secure against adaptive chosen ciphertext attacks.

When encrypting a plaintext one can optionally provide _associated data_ that
should be authenticated but not encrypted. That is, the encryption with
associated data ensures authenticity (ie. who the sender is) and integrity (ie.
data has not been tampered with) of that data, but not its secrecy (see
[RFC 5116](https://tools.ietf.org/html/rfc5116)). This is often used for binding
encryptions to a context. For example, in a banking database the contents of a
row (e.g. bank account balance) can be encrypted using the customer's id as
_associated data_. This would prevent swapping encrypted data between customers'
records.

Minimal properties:

- _plaintext_ and _associated data_ can have arbitrary length
   (within the range 0..2<sup>32</sup> bytes)
- CCA2 security
- at least 80-bit authentication strength
- there are no secrecy or knowledge guarantees wrt. to the value of _associated
  data_
- can encrypt at least 2<sup>32</sup> messages with a total of 2<sup>50</sup>
  bytes so that no attack has success probability larger than 2<sup>-32</sup>

## Streaming Authenticated Encryption with Associated Data

Streaming AEAD primitive (Streaming Authenticated Encryption with Associated
Data) provides authenticated encryption for streaming data, and is useful when
the data to be encrypted is too large to be processed in a single step.  Typical
use cases include encryption of large files or encryption of live data
streams.

The underlying encryption modes are selected so that partial plaintext
can be obtained fast by decrypting and authenticating just a part of the
ciphertext, without need of processing the entire ciphertext.

Encryption must be done in one session. There is no possibility to modify an
existing ciphertext or to append to it (other than to reencrypt the entire file
again).

Instances of _Streaming AEAD_ follow the OAE2 definition proposed in the
paper [_"Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"_
by Hoang, Reyhanitabar, Rogaway and
Vizár](https://eprint.iacr.org/2015/189.pdf).

Minimal properties:

- _plaintext_ can have arbitrary length within the range 0..2<sup>38</sup>
  and _associated data_ can have arbitrary length within the range
  0..2<sup>31</sup>-1 bytes
- CCA2 security
- at least 80-bit authentication strength
- there are no secrecy or knowledge guarantees wrt. to the value of _associated
  data_
- can encrypt at least 2<sup>32</sup> messages with a total of 2<sup>68</sup>
  bytes so that no attack with up to 2<sup>32</sup> chosen plaintexts/chosen
  ciphertexts has success probability larger than 2<sup>-32</sup>.

## Deterministic Authenticated Encryption with Associated Data

Deterministic AEAD primitive (Deterministic Authenticated Encryption with
Associated Data, DAEAD) provides encryption with a _deterministic property_:
encrypting the same data always yields the same ciphertext. Such encryption is
useful e.g. for key wrapping or for some schemes for searching on encrypted data
(see [RFC 5297, Section 1.3](https://tools.ietf.org/html/rfc5297#section-1.3)
for more info).  However, because of deterministic property, implementations of
this primitive are **not semantically secure**.


As for (regular) [AEAD](#authenticated-encryption-with-associated-data), when
using Deterministic AEAD to encrypt a plaintext one can optionally provide
_associated data_ that should be authenticated but not encrypted.  That is, the
encryption with associated data ensures authenticity (ie. who the sender is) and
integrity (ie. data has not been tampered with) of that data, but not its
secrecy (see [RFC 5116](https://tools.ietf.org/html/rfc5116)).


Minimal properties:

- _plaintext_ and _associated data_ can have arbitrary length
  (within the range 0..2<sup>32</sup> bytes)
- 128-bit security level against multi-user attacks with up to 2<sup>32</sup>
  keys; that means if an adversary obtains 2<sup>32</sup> ciphertexts of the
  same message encrypted under 2<sup>32</sup> keys, they need to do
  2<sup>128</sup> computations to obtain a single key.
- at least 80-bit authentication strength
- there are no secrecy or knowledge guarantees wrt. to the value of _associated
  data_

## Message Authentication Code

MAC primitive (Message Authentication Code) provides symmetric message
authentication. A sender sharing a _symmetric key_ with a recipient can compute
an _authentication tag_ for a given message, that allows for verifying that the
message comes from the sender and that it has not been modified. Instances of
MAC primitive are secure against existential forgery under chosen plaintext
attack, and can be deterministic or randomized. This interface should be used
for authentication only, and not for other purposes like generation of
pseudorandom bytes.


Minimal properties:

- secure against existential forgery under CPA
- at least 128-bit security, also in multi-user scenarios (when an attacker is
  not targeting a specific key, but any key from a set of up to 2<sup>32</sup>
  keys)
- at least 80-bit authentication strength

## Pseudo Random Function Families

The PRF set primitive allows to redact data in a deterministic fashion, for
example personal identifiable information or internal IDs, or to come up with a
user ID from user information without revealing said information in the ID. This
allows someone with access to the output of the PRF without access to the key do
some types of analysis, while limiting others.

Note that while in theory PRFs can be used in other ways, for example for
encryption or message authentication, the corresponding primitives should only
be used for these use cases.

WARNING: Since PRFs operate deterministically on their input, using a PRF to
redact will not automatically provide anonymity, but only provide pseudonymity.
It is an important tool to build privacy aware systems, but has to be used
carefully.

Minimal properties:

-   without knowledge of the key the PRF is indistinguishable from a random
    function
-   at least 128-bit security, also in multi-user scenarios (when an attacker is
    not targeting a specific key, but any key from a set of up to 2<sup>32</sup>
    keys)
-   at least 16 byte of output available

WARNING: While HMAC-SHA-2 and HKDF-SHA-2 behave like a cryptographically secure
hash function if the key is revealed, and still provide some protection against
revealing the input, AES-CMAC is only secure as long as the key is secure.

Since Tink operates on key sets, this primitive exposes a corresponding set of
PRFs instead of a single PRF. The PRFs are indexed by a 32 bit key id. This can
be used to rotate the key used to redact a piece of information, without losing
the previous association.

## Hybrid Encryption

Hybrid Encryption combines the efficiency of symmetric encryption with the
convenience of public-key encryption: to encrypt a message a fresh symmetric key
is generated and used to encrypt the actual plaintext data, while the
recipient’s public key is used to encrypt the symmetric key only, and the final
ciphertext consists of the symmetric ciphertext and the encrypted symmetric
key.

**WARNING** Hybrid Encryption does not provide authenticity, that is the
recipient of an encrypted message does not know the identity of the sender.
Similar to general public-key encryption schemes the security goal of Hybrid
Encryption is to provide privacy only. In other words, Hybrid Encryption is
secure if and only if the recipient can accept anonymous messages or can rely
on other mechanism to authenticate the sender.

The functionality of Hybrid Encryption is represented in Tink as a pair of
primitives: HybridEncrypt for encryption of data, and HybridDecrypt for
decryption.  Implementations of these primitives are secure against adaptive
chosen ciphertext attacks.

In addition to the plaintext encryption accepts an extra parameter _context
info_, which usually is public data implicit from the context, but should be
bound to the resulting ciphertext, i.e. the ciphertext allows for checking the
integrity of _context info_ but there are no guarantees wrt. to secrecy or
authenticity of _context info_.  The actual _context info_ can be empty or null,
but to ensure the correct decryption of the resulting ciphertext the same value
must be provided for decryption operation.

A concrete implementation of hybrid encryption can implement the binding of
_context info_ to the ciphertext in various ways, for example:

- use context\_info as "associated data"-input for the employed AEAD symmetric
  encryption (cf. [RFC 5116](https://tools.ietf.org/html/rfc5116)).
- use context\_info as "CtxInfo"-input for HKDF (if the implementation uses HKDF
  as key derivation function, cf.
  [RFC 5869](https://tools.ietf.org/html/rfc5869)).

Furthermore, the DataEncapsulationMechanism can be achieved using either an Aead
primitive or a Determinisitic Aead.

Minimal properties:

- _plaintext_ and _context info_ can have arbitrary length
  (within the range 0..2<sup>32</sup> bytes)
- secure against chosen ciphertext attacks
- 128-bit security for EC based schemes,
  112-bit security for RSA based schemes (i.e. allow 2048 bit keys)

## Digital Signatures

Digital Signatures provide functionality of signing data and verification of
signatures.  It ensures the authenticity and the integrity of the signed data,
but not its secrecy.

The functionality of Digital Signatures is represented in Tink as a pair of
primitives: PublicKeySign for signing of data, and PublicKeyVerify for
verification of signatures.  Implementations of these primitives are secure
against adaptive chosen-message attacks.

Minimal properties:

- data to be signed can have arbitrary length
- 128-bit security for EC based schemes
- 112-bit security for RSA based schemes (i.e. allow 2048 bit keys)
