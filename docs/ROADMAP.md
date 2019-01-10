# Tink Feature Roadmap

(_based on Bazel Feature Roadmap_)

This document describes the Tink team's plans for introducing features. Note
that this roadmap only includes features that the Tink team itself intends to
support. We anticipate that a number of other features will be added by code
contributors.

In the following list, each feature is associated with a corresponding
milestone. The convention for the priorities are:

*   **P0** feature will block the milestone; we will delay the milestone date
    until the feature is shipped.

*   **P1** feature can delay the milestone if the feature can be shipped with a
    reasonable delay.

*   **P2** feature will be dropped and rescheduled for later rather than
    delaying the milestone. We will update this list when reaching each
    milestone; some milestones may also be refined if appropriate.

## Planned feature list

### 1.2.0

Tentative release date: July 2018 (it was June 2018, but we need more time to
prepare the Obj-C release).

*   Java

    *   P1. Hybrid encryption with X25519 and ChaCha20Poly1305.

*   C++

    *   P0. Initial release, feature parity with [Java
        1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).
    *   P0. Easy installation.
    *   P1. Integration with Google Cloud KMS and AWS KMS.

*   Objective-C

    *   P0. Initial release, feature parity with [Java
        1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).
    *   P0. Easy installation.
    *   P1. Integration with iOS Keychain.

### 1.3.0

Tentative release date: February 2019.

Tentative new features:

*   Java

    *   P0. Integration with Cloud KMS/AWS KMS: streaming envelope encryption
    *   P1. AEAD: XCHACHA20-POLY1305
    *   P1. Signature: RSA-SSA-PKCS1, RSA-PSS
    *   P2. Streaming hybrid encryption

*   C++/Obj-C

    *   P0. Integration with Cloud KMS/AWS KMS: key storage and (streaming)
        envelope encryption
    *   P0. Streaming AEAD: AES-GCM-HKDF-STREAMING, AES-CTR-HMAC-STREAMING
    *   P0. Deterministic AEAD: AES-SIV
    *   P0. Digital signature: ED25519
    *   P1. AEAD: XCHACHA20-POLY1305
    *   P1. Signature: RSA-SSA-PKCS1, RSA-PSS
    *   P2. Nonce reuse resistant AEAD: AES-GCM-SIV

*   Go

    *   P0. AEAD: AES-GCM, AES-CTR-HMAC-AEAD
    *   P0. MAC: HMAC-SHA2
    *   P0. Signature: ECDSA with NIST curves
    *   P0. Hybrid encryption: ECIES with NIST curves and AEAD
    *   P1. AEAD: XCHACHA20-POLY1305
    *   P1. Integration with Cloud KMS/AWS KMS: key storage and envelope
        encryption
    *   P2. Signature: ED25519
    *   P2. Deterministic AEAD: AES-SIV

### 1.4.0

Tentative release date: August 2019.

Tentative new features:

*   Go/Java/C++/Obj-C

    *   P0. Benchmarking
    *   P0. Full integration with Cloud KMS/AWS KMS: key storage, (streaming)
        envelope encryption, hybrid encryption and digital signature
    *   P0. Initial support for Cloud HSM/AWS HSM
    *   P1. Feature parity across platforms.

*   JavaScript

    *   P0. Initial release that supports modern browsers

*   Python

    *   P0. Initial CLIF-based release that can replace Keyczar.
