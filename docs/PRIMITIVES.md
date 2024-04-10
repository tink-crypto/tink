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

See https://developers.google.com/tink/prf

## Hybrid Encryption

See https://developers.google.com/tink/hybrid

## Digital Signatures

See https://developers.google.com/tink/digital-signature
