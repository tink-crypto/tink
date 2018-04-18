# Tink's Security and Usability Design Goals

*   **Simplicity** Tink provides APIs that are simple and easy to use correctly.
    Most crypto operations such as data encryption, digital signatures, etc. can
    be done with only a few lines of code.

*   **High-level** Tink's interfaces abstract away from the underlying
    implementation. Instances are usable without knowing the underlying class
    that implements it. It is also possible to change the underlying
    implementation of an interface without changes to the call of the interface.
    Interfaces have security guarantees that must be satisfied by each primitive
    implementing the interface. This may exclude some encryption modes. Rather
    than adding them to existing interfaces and weakening the guarantees of the
    interface it is possible to add new interfaces and describe the security
    guarantees appropriately.

*   **Misuse-proof** Tink assumes that the attacker has complete freedom in
    calling methods of a high level interface; under this assumption the
    security is not compromised. For example, if the underlying encryption mode
    requires nonces and is insecure if nonces are reused then the interface does
    not allow to pass nonces. Tink also assumes that the attacker can get access
    to memory passed into a method, even if a crypto operation (e.g. decryption)
    failed.

*   **Extensibility** Tink makes it easy to support new primitives, new
    algorithms, new ciphertext formats, new key management systems, etc.

*   **Agility** Tink provides built-in crypto agility. It supports key rotation,
    deprecation of obsolete schemes and adaptation of new ones. For example, if
    an implementation of a crypto primitive is found broken, you can switch to a
    different implementation by rotating keys, without changing or recompiling
    code.

*   **Interoperability** Tink produces and consumes ciphertexts that are
    compatible with existing crypto libraries. Tink supports encrypting or
    storing keys in Amazon KMS, Google Cloud KMS, Android Keystore, and it is
    easy to support other key management systems.

*   **Versatility** No part of Tink is hard to replace or remove. All components
    are recombinant, and can be selected and assembled in various combinations.
    For example, if you need only digital signatures, you can exclude symmetric
    key encryption components.

*   **Readability** Tink shows crypto properties (i.e., whether safe against
    chosen-ciphertext attacks) right in the interfaces, allowing security
    auditors and automated tools quickly discovering incorrect usages. Tink
    provides standalone static types for potential dangerous operations (e.g.,
    loading cleartext keys from disk), allowing discovering, restricting,
    monitoring and logging their usages.
