# Tink Primitives

[Tink](https://github.com/google/tink) performs cryptographic tasks via
so-called
[*primitives* and *interfaces*](https://developers.google.com/tink/design/primitives_and_interfaces).

## Supported primitives and their implementations

### Primitives supported by language

See https://developers.google.com/tink/primitives-by-language

### Primitive implementations supported by language

See https://developers.google.com/tink/supported-key-types

## General properties of all primitives

-   stateless (hence thread-safe)
-   copy-safe (for the parameters)
-   at least 128-bit security (with an exception for RSA)

## Authenticated Encryption with Associated Data

See https://developers.google.com/tink/aead

## Streaming Authenticated Encryption with Associated Data

See https://developers.google.com/tink/streaming-aead

## Deterministic Authenticated Encryption with Associated Data

See https://developers.google.com/tink/deterministic-aead

## Message Authentication Code

See https://developers.google.com/tink/mac

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

See https://developers.google.com/tink/hybrid

## Digital Signatures

See https://developers.google.com/tink/digital-signature
