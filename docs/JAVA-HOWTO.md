# Tink for Java HOW-TO

This document contains instructions and Java code snippets for common tasks in
[Tink](https://github.com/tink-crypto/tink-java).

If you want to contribute code to the Java implementation, please read the [Java
hacking guide](JAVA-HACKING.md).

## Setup instructions

See https://developers.devsite.corp.google.com/tink/tink-setup#java for setup
instructions.

## API documentation

*   Java:
    *   [1.9.0](https://google.github.io/tink/javadoc/tink/1.9.0)
    *   [HEAD-SNAPSHOT](https://google.github.io/tink/javadoc/tink/HEAD-SNAPSHOT)
*   Android:
    *   [1.9.0](https://google.github.io/tink/javadoc/tink-android/1.9.0)
    *   [HEAD-SNAPSHOT](https://google.github.io/tink/javadoc/tink-android/HEAD-SNAPSHOT)

## Important warnings

**Do not use APIs which have fields or methods marked with the `@Alpha`
annotation.** They can be modified in any way, or even removed, at any time.
They are in the package, but not for official, production release, but only for
testing.

**Do not use APIs in `com.google.crypto.tink.subtle`.** While they're generally
safe to use, they're not meant for public consumption and can be modified in any
way, or even removed, at any time.

## Initializing Tink

Tink provides customizable initialization, which allows you to choose specific
implementations (identified by _key types_) of desired primitives. This
initialization happens via _registration_ of the implementations.

For example, if you want to use all implementations of all primitives in Tink,
the initialization would be:

```java
    import com.google.crypto.tink.config.TinkConfig;

    TinkConfig.register();
```

To use only implementations of the AEAD primitive:

```java
    import com.google.crypto.tink.aead.AeadConfig;

    AeadConfig.register();
```

For custom initialization the registration proceeds directly via the
`Registry` class:

```java
    import com.google.crypto.tink.Registry;
    import my.custom.package.aead.MyAeadKeyManager;

    // Register a custom implementation of AEAD.
    Registry.registerKeyManager(new MyAeadKeyManager());

```

## Generating new keys and keysets

Each `KeyManager`-implementation provides `newKey(..)`-methods that generate new
keys of the corresponding key type. However, to avoid accidental leakage of
sensitive key material, you should avoid mixing key(set) generation with
key(set) usage in code. To support the separation between these activities, Tink
provides a command-line tool called [Tinkey](TINKEY.md), which can be used for
common key management tasks.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Java code, you can use
[`KeysetHandle`](https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/KeysetHandle.java).
For example, you can generate a keyset containing a randomly generated
AES128-GCM key as follows.

```java
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.aead.PredefinedAeadParameters;

    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        PredefinedAeadParameters.AES128_GCM);
```

## Serializing keysets

After generating key material, you might want to serialize it in order to
persist it to a storage system, e.g., writing to a file.

```java
    import com.google.crypto.tink.InsecureSecretKeyAccess;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.TinkJsonProtoKeysetFormat;
    import com.google.crypto.tink.aead.PredefinedAeadParameters;
    import java.nio.Files;

    // Generate the key material...
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        PredefinedAeadParameters.AES128_GCM);

    // and serialize it to a string.
    String keysetFilename = "my_keyset.json";
    String serializedKeyset =
        TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
```

Parsing can be done with `TinkJsonProtoKeysetFormat.parseKeyset`. If the keyset
has no secret key material, the method `serializeKeysetWithoutSecret` can be
used (which does not require `InsecureSecretKeyAccess`).

Storing keysets unencrypted on disk is not recommended. Tink supports encrypting
keysets with master keys stored in remote key management systems, see for
example
https://developers.devsite.corp.google.com/tink/client-side-encryption#java.

## Obtaining and using primitives

[Primitives](PRIMITIVES.md) represent cryptographic operations offered by Tink,
hence they form the core of the Tink API. A primitive is an interface which
specifies what operations are offered by the primitive. A primitive can have
multiple implementations, and you choose a desired implementation by using a key
of a corresponding type (see [this
document](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for further details).

A list of primitives and the implementations currently supported by Tink in Java
can be found [here](PRIMITIVES.md#java).

You obtain a primitive by calling the method `getPrimitive(classObject)` of a
`KeysetHandle`, where the `classObject` is the class object corresponding to the
primitive (for example `Aead.class` for AEAD).

### Symmetric Key Encryption

You can obtain and use an
[AEAD](PRIMITIVES.md#authenticated-encryption-with-associated-data)
(Authenticated Encryption with Associated Data) primitive to encrypt or decrypt
data:

```java
    import com.google.crypto.tink.Aead;
    import com.google.crypto.tink.aead.PredefinedAeadParameters;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        PredefinedAeadParameters.AES128_GCM);

    // 2. Get the primitive.
    Aead aead = keysetHandle.getPrimitive(Aead.class);

    // 3. Use the primitive to encrypt a plaintext,
    byte[] ciphertext = aead.encrypt(plaintext, aad);

    // ... or to decrypt a ciphertext.
    byte[] decrypted = aead.decrypt(ciphertext, aad);
```

### Deterministic symmetric key encryption

You can obtain and use a
[DeterministicAEAD](PRIMITIVES.md#deterministic-authenticated-encryption-with-associated-data)
(Deterministic Authenticated Encryption with Associated Data primitive to
encrypt or decrypt data:

```java
    import com.google.crypto.tink.daead.PredefinedDeterministicAeadParameters;
    import com.google.crypto.tink.KeysetHandle;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        PredefinedDeterministicAeadParameters.AES256_SIV);

    // 2. Get the primitive.
    DeterministicAead daead =
       keysetHandle.getPrimitive(DeterministicAead.class);

    // 3. Use the primitive to deterministically encrypt a plaintext,
    byte[] ciphertext = daead.encryptDeterministically(plaintext, aad);

    // ... or to deterministically decrypt a ciphertext.
    byte[] decrypted = daead.decryptDeterministically(ciphertext, aad);
```

### Symmetric key encryption of streaming data

See
https://developers.devsite.corp.google.com/tink/encrypt-large-files-or-data-streams#java

### Message Authentication Code

See
https://developers.devsite.corp.google.com/tink/protect-data-from-tampering#java

### Digital signatures

See https://developers.devsite.corp.google.com/tink/digitally-sign-data

### Hybrid encryption

See https://developers.devsite.corp.google.com/tink/exchange-data#java

### Envelope encryption

Via the AEAD interface, Tink supports
[envelope encryption](KEY-MANAGEMENT.md#envelope-encryption).

For example, you can perform envelope encryption with a Google Cloud KMS key at
`gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar`
using the credentials in `credentials.json` as follows:

```java
    import com.google.crypto.tink.Aead;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KmsClients;
    import com.google.crypto.tink.aead.KmsEnvelopeAeadKeyManager;
    import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;

    // 1. Generate the key material.
    String kmsKeyUri =
        "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar";
    KeysetHandle handle =
        KeysetHandle.generateNew(
            KmsEnvelopeAeadKeyManager.createKeyTemplate(
                kmsKeyUri, KeyTemplates.get("AES128_GCM")));

    // 2. Register the KMS client.
    KmsClients.add(new GcpKmsClient()
        .withCredentials("credentials.json"));

    // 3. Get the primitive.
    Aead aead = handle.getPrimitive(Aead.class);

    // 4. Use the primitive.
    byte[] ciphertext = aead.encrypt(plaintext, aad);
```

## Key rotation

Support for key rotation in Tink is provided via the
[`KeysetHandle.Builder`](https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/KeysetHandle.java)
class.

You have to provide a `KeysetHandle`-object that contains the keyset that should
be rotated, and a specification of the new key via a
[`Parameters`](https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/Parameters.java)
object.

```java
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeysetManager;

    KeysetHandle keysetHandle = ...;   // existing keyset
    KeysetHandle.Builder builder = KeysetHandle.newBuilder(keysetHandle);
    builder.addEntry(KeysetHandle.generateEntryFromParameters(
      ChaCha20Poly1305Parameters.create()).withRandomId());
    KeysetHandle keysetHandleWithAdditionalEntry = builder.build();
```

After a successful rotation, the resulting keyset contains a new key generated
according to the specification in the parameters object. For the rotation to
succeed the `Registry` must contain a key manager for the key type specified in
`keyTemplate`.

Alternatively, you can use [Tinkey](TINKEY.md) to rotate or manage a keyset.

## Custom implementation of a primitive

**NOTE**: The usage of **custom key managers should be enjoyed responsibly**. We
(i.e. Tink developers) have no way of checking or enforcing that a custom
implementation satisfies security properties of the corresponding primitive
interface, so it is up to the implementer and the user of the custom
implementation ensure the required properties are met.

The main cryptographic operations offered by Tink are accessible via so-called
_primitives_, which are interfaces that represent corresponding cryptographic
functionalities. While Tink comes with several standard implementations of
common primitives, it also allows for adding custom implementations of
primitives. Such implementations allow for seamless integration of Tink with
custom third-party cryptographic schemes or hardware modules, and in combination
with [key rotation](#key-rotation) features, enables the painless migration
between cryptographic schemes.

To create a custom implementation of a primitive proceed as follows:

1.  Determine for which _primitive_ a custom implementation is needed.
2.  Define protocol buffers that hold key material and parameters for the custom
    cryptographic scheme; the name of the key protocol buffer (a.k.a. type URL)
    determines the _key type_ for the custom implementation.
3.  Implement a
    [`KeyManager`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/KeyManager.java)
    interface for the _primitive_ from step #1 and the _key type_ from step #2.

To use a custom implementation of a primitive in an application, register with
the
[`Registry`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/Registry.java)
the custom `KeyManager` implementation (from step #3 above) for the custom key
type (from step #2 above):

```java
    Registry.registerKeyManager(keyManager);
```

Afterwards the implementation will be accessed automatically by the
`keysetHandle.getPrimitive` corresponding to the primitive (when keys of the
specific key type are in use). It can also be retrieved directly via
`Registry.getKeyManager(keyType)`.

When defining the protocol buffers for the key material and parameters (step #2
above), you should provide definitions of three messages:

 * `...Params`: parameters of an instantiation of the primitive,
   needed when a key is being used.
 * `...Key`: the actual key proto, contains the key material and the
   corresponding `...Params` proto.
 * `...KeyFormat`: parameters needed to generate a new key.

Here are a few conventions/recommendations when defining these messages (see
[tink.proto](https://github.com/google/tink/blob/master/proto/tink.proto) and
definitions of [existing key
types](https://github.com/google/tink/blob/master/proto/) for details):

 * `...Key` should contain a version field (a monotonic counter, `uint32 version;`),
   which identifies the version of implementation that can work with this key.
 * `...Params` should be a field of `...Key`, as by definition `...Params`
   contains parameters needed when the key is being used.
 * `...Params` should be also a field of `...KeyFormat`, so that given `...KeyFormat`
   one has all information it needs to generate a new `...Key` message.

Alternatively, depending on the use case requirements, you can skip step #2
entirely and re-use an existing protocol buffer messages for the key material.
In such a case, you should not configure the Registry via the `Config`-class, but
rather register the needed `KeyManager`-instances manually.

For a concrete example, let's assume that we'd like a custom implementation of
the
[`Aead`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/Aead.java)
primitive (step #1). We define then three protocol buffer messages (step #2):

 * `MyCustomAeadParams`: holds parameters needed for the use of the key material.
 * `MyCustomAeadKey`: holds the actual key material and parameters needed for its use.
 * `MyCustomAeadKeyFormat`: holds parameters needed for generation of a new `MyCustomAeadKey`-key.

```proto
    syntax = "proto3";
    package mycompany.mypackage;

    message MyCustomAeadParams {
      uint32 iv_size = 1;     // size of initialization vector in bytes
    }

    message MyCustomAeadKeyFormat {
      MyCustomAeadParams params = 1;
      uint32 key_size = 2;    // key size in bytes
    }

    // key_type: type.googleapis.com/mycompany.mypackage.MyCustomAeadKey
    message MyCustomAeadKey {
        uint32 version = 1;
        MyCustomAeadParams params = 2;
        bytes key_value = 3;  // the actual key material
    }
```

The corresponding _key type_ in Java is defined as

```java
    String keyType = "type.googleapis.com/mycompany.mypackage.MyCustomAeadKey";`
```

and the corresponding _key manager_ implements (step #3) the interface
[`KeyManager<Aead>`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/KeyManager.java)

```java
    class MyCustomAeadKeyManager implements KeyManager<Aead> {
      // ...
    }
```

After registering `MyCustomAeadKeyManager` with the Registry, it will be used
when you call `keysetHandle.getPrimitive(Aead.class)`.
