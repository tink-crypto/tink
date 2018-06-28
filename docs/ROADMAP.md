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

Tentative release date: December 2018.

*   Java

    *   P1. Authenticated Public Key Encryption.
    *   P1. Initial support for strict JOSE.
    *   P2. JNI for better performance.

*   C++

    *   P0. Feature parity with [Java
        1.1.0](https://github.com/google/tink/releases/tag/v1.1.0).

*   Objective-C

    *   P0. Feature parity with [Java
        1.1.0](https://github.com/google/tink/releases/tag/v1.1.0).

*   C#

    *   P0. Initial release, feature parity with [Java
        1.0.0](https://github.com/google/tink/releases/tag/v1.1.0).
    *   P1. Integration with Azure Key Vault.

*   Go

    *   P1. Initial release, feature parity with [Java
        1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).
    *   P2. Integration with Google Cloud KMS and AWS KMS.

*   Javascript/NodeJS

    *   P1. Initial release, feature parity with [Java
        1.0.0](https://github.com/google/tink/releases/tag/v1.0.0).

### 1.4.0

Tentative release date: June 2019.

*   Java

    *   P0. Stable strict JOSE APIs.
    *   P1. More streaming APIs: StreamingMac and StreamingAead with append and
        random write.
    *   P1. Benchmarking.

*   C++/Objective-C/Go/C#/Javascript/NodeJS

    *   P0. Feature parity with Java 1.4.0.

*   C++

    *   P1. Windows support.
