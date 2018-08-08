# Tink's Security and Usability Design Goals

*   **Security** Tink is built on top of existing libraries such as BoringSSL
    and Java Cryptography Architecture, but includes countermeasures to many
    weaknesses in these libraries, which were discovered by Project Wycheproof,
    another project from our team.

*   **Easiness** Most crypto operations such as data encryption, digital
    signatures, etc. can be done with only a few lines of code. Tink's
    interfaces abstract away from the underlying implementations. Interfaces are
    usable without knowing the underlying class that implements it.

*   **Hard-to-misuse** Tink aims to eliminate as many potential misuses as
    possible. For example, if the underlying encryption mode requires nonces and
    is insecure if nonces are reused, then Tink does not allow the passing of
    nonces by the user. Interfaces have security guarantees that must be
    satisfied by each primitive implementing the interface. This may exclude
    some encryption modes. Rather than adding them to existing interfaces and
    weakening the guarantees of the interface it is possible to add new
    interfaces and describe the security guarantees appropriately.

*   **Readability** Tink shows the security guarantees (e.g., safe against
    chosen-ciphertext attacks) right in the interfaces, allowing security
    auditors and automated tools to quickly discover usages where the security
    guarantees don’t match the security requirements. Tink also separates APIs
    for potential dangerous operations (e.g., loading cleartext keys from disk),
    allowing discovering, restricting, monitoring and logging their usages.

*   **Extensibility** Tink makes it easy to support new primitives, new
    algorithms, new ciphertext formats, new key management systems, etc.

*   **Agility** Tink provides built-in crypto agility. It supports key rotation,
    deprecation of obsolete schemes and adaptation of new ones. For example, if
    an implementation of a crypto primitive is found broken, you can switch to a
    different implementation by rotating keys, without changing or recompiling
    code.

*   **Interoperability** Tink produces and consumes ciphertexts that are
    compatible with existing crypto libraries. Tink supports encrypting or
    storing keys in Amazon KMS, Google Cloud KMS, Android Keystore, iOS
    Keychain, and it is easy to add support for custom key management systems.

*   **Versatility** No part of Tink is hard to replace or remove. All components
    are recombinant, and can be selected and assembled in various combinations.
    For example, if you need only digital signatures, you can exclude symmetric
    key encryption components.
