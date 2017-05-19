# Tink Java HOW-TO

The following subsections present instructions and/or Java-snippets for some
common tasks in [Tink](https://github.com/google/tink).

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives.  This
intialization happens via _registration_ of the implementations.  To register
standard implementations of primtives one can use
`registerStandardKeyTypes()`-methods of corresponding factories.  Example if one
wants to use the standard implementations of AEAD and MAC primitives offered by
Tink, the initialization would look as follows:

``` java
    import com.google.cloud.crypto.tink.aead.AeadFactory;
    import com.google.cloud.crypto.tink.mac.MacFactory;
    // (...)

    // Register standard implementations of AEAD and MAC primitives.
    AeadFactory.registerStandardKeyTypes();
    MacFactory.registerStandardKeyTypes();
```

For custom initialization the registration proceeds directly via `Registry`-class:

``` java
    import com.google.cloud.crypto.tink.Registry;
    import com.google.cloud.crypto.tink.aead.AesCtrHmacAeadKeyManager;
    import my.custom.package.aead.MyAeadKeyManager;
    // (...)

    // Register only one Tink-implementation of AEAD.
    Registry.INSTANCE.registerKeyManager(
        AesCtrHmacAeadKeyManager.TYPE_URL, new AesCtrHmacAeadKeyManager());

    // Register a custom implementation of AEAD.
    Registry.INSTANCE.registerKeyManager(
        MyAeadKeyManager.TYPE_URL, new MyAeadKeyManager());

```

## Generating New Key(set)s

Each `KeyManager`-implementation provides `newKey(..)`-methods that generate new
keys of the corresponding key type.  However to avoid accidental leakage of
sensitive key material one should be careful with mixing key(set) generation
with key(set) useage in code.  To support the separation between these
activities Tink package provides a command-line tool
called [Tinkey](https://github.com/google/tink/tree/master/tools/tinkey), which
can be used for common key management tasks.  Moreover, there is also
[`KmsEncryptedKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/KmsEncryptedKeysetHandle.java)-class,
which enables working with keysets in which the sensitive key material is
encrypted with a KMS-managed key.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Java code, one can use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandle.java)-class:

``` java
    KeysetHandle keysetHandle = CleartextKeysetHandle.generateNew(keyTemplate);
```

where `keyTemplate` can be initialized with one of pre-generated templates from
[tools/tinkey/keytemplates](https://github.com/google/tink/tree/master/tools/tinkey/keytemplates)-folder.
Alternatively, one can use also
[`KeysetManager`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/KeysetManager.java)-class.

## Loading Existing Keysets
Via [`KmsEncryptedKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/KmsEncryptedKeysetHandle.java) or
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/CleartextKeysetHandle.java),

TODO: write more in this section

## Creating and Using a Primitive

After all needed KeyManagers have been registered, one instantiates a primitive
via the corresponding factory.  For example, here is how to instantiate and use
AEAD-primitive:

``` java
    import com.google.cloud.crypto.tink.Aead;
    import com.google.cloud.crypto.tink.aead.AeadFactory;
    import com.google.cloud.crypto.tink.KeysetHandle;
    // (...)

    // 1. Get the key material.
    KeysetHandle keysetHandle = ...;
    // 2. Get the primitive.
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    // 3. Use the primitive.
    byte[] ciphertext = aead.encrypt(plaintext, aad);
```


## Key Rotation
Via [Tinkey](https://github.com/google/tink/tree/master/tools/tinkey) or
[`KeysetManager`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/cloud/crypto/tink/KeysetManager.java).

TODO: write more in this section

## Custom Implementation of a Primitive
TODO: write this section

## Adding a Custom Primitive
TODO: write this section
