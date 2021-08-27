# Tink Feature Roadmap

This document describes the Tink team's plans for introducing features.

This roadmap only includes features that the Tink team itself intends to
implement. Other features may be added by code contributors.

In the following list, features are bundled together by milestone and and then
by the language implementation they're associated with.

Each feature is prefixed with a priority level. The definition of the priority
levels are are:

*   **P0**:  The feature will block the milestone. We will delay the milestone
    date until the feature is shipped.

*   **P1**: The feature can delay the milestone if the feature can be shipped
    with a reasonable delay.

*   **P2**:  The feature will be dropped and rescheduled for later rather than
    delaying the milestone.

This list will be updated periodically and milestones may be refined if
appropriate.

## Upcoming milestones

### 1.3.0

Tentative release date: November 2019.

Tentative new features:

*   Java

    *   P1. AEAD: XCHACHA20-POLY1305
    *   P1. Signature: RSA-SSA-PKCS1, RSA-PSS

*   C++

    *   P0. Integration with Cloud KMS/AWS KMS: key storage and envelope
        encryption
    *   P0. Streaming AEAD: AES-GCM-HKDF-STREAMING, AES-CTR-HMAC-STREAMING
    *   P0. Deterministic AEAD: AES-SIV
    *   P0. Digital signature: ED25519
    *   P1. AEAD: XCHACHA20-POLY1305, AES-GCM-SIV
    *   P1. Signature: RSA-SSA-PKCS1, RSA-PSS

*   Objective-C

    *   P0. Deterministic AEAD: AES-SIV
    *   P0. Digital signature: ED25519
    *   P1. AEAD: XCHACHA20-POLY1305
    *   P1. Signature: RSA-SSA-PKCS1, RSA-PSS

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

Tentative release date: February 2019.

Tentative new features:

*   Java

    *   P0. AEAD: AES-GCM-SIV
    *   P1. Integration with Cloud KMS/AWS KMS: streaming envelope encryption
    *   P1. Full integration with Cloud KMS/AWS KMS: key storage, (streaming)
        envelope encryption, hybrid encryption and digital signature
    *   P1. Initial support for Cloud HSM/AWS HSM
    *   P2. Nonce reuse resistant AEAD: AES-GCM-SIV


*   C++

    *   P1. Integration with Cloud KMS/AWS KMS: streaming envelope encryption
    *   P1. Full integration with Cloud KMS/AWS KMS: key storage, (streaming)
        envelope encryption, hybrid encryption and digital signature
    *   P1. Initial support for Cloud HSM/AWS HSM
    *   P1. Feature parity across implementations
    *   P2. Nonce reuse resistant AEAD: AES-GCM-SIV

*   Objective-C

    *   P0. Streaming AEAD: AES-GCM-HKDF-STREAMING, AES-CTR-HMAC-STREAMING
    *   P1. AEAD: AES-GCM-SIV
    *   P1. Feature parity across implementations
    *   P2. Nonce reuse resistant AEAD: AES-GCM-SIV


*   Go

    *   P0. Streaming AEAD: AES-GCM-HKDF-STREAMING, AES-CTR-HMAC-STREAMING
    *   P1. AEAD: AES-GCM-SIV
    *   P1. Full integration with Cloud KMS/AWS KMS: key storage, (streaming)
        envelope encryption, hybrid encryption and digital signature
    *   P1. Initial support for Cloud HSM/AWS HSM
    *   P1. Feature parity across implementations
    *   P2. Nonce reuse resistant AEAD: AES-GCM-SIV



*   JavaScript

    *   P0. Initial release that supports modern browsers

*   Python

    *   P0. Initial CLIF-based release that can replace Keyczar.

## Past Milestones

### 1.2.0

Release date: August 2018

[Release Notes](https://github.com/google/tink/releases/tag/v1.2.0)

*   Java

    *   P1. Hybrid encryption with X25519 and ChaCha20Poly1305.

*   C++

    *   P0. Initial release, feature parity with
        [Java 1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).
    *   P0. Easy installation.
    *   P1. Integration with Google Cloud KMS and AWS KMS.

*   Objective-C

    *   P0. Initial release, feature parity with
        [Java 1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).
    *   P0. Easy installation.
    *   P1. Integration with iOS Keychain.
