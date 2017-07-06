# Tink Java HOW-TO

The following subsections present instructions and/or Java-snippets for some
common tasks in [Tink](https://github.com/google/tink).

## Initializing Tink

Tink provides customizable initialization, which allows for choosing specific
implementations (identified by _key types_) of desired primitives.  This
initialization happens via _registration_ of the implementations.  To register
standard implementations of primitives one can use
`registerStandardKeyTypes()`-methods of corresponding `Config`-classes.  For
example if one wants to use the standard implementations of AEAD and MAC
primitives offered by Tink, the initialization would look as follows:

``` java
    import com.google.crypto.tink.aead.AeadConfig;
    import com.google.crypto.tink.mac.MacConfig;
    // (...)

    // Register standard implementations of AEAD and MAC primitives.
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
```

For custom initialization the registration proceeds directly via `Registry`-class:

``` java
    import com.google.crypto.tink.Registry;
    import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
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
with key(set) usage in code.  To support the separation between these
activities Tink package provides a command-line tool
called [Tinkey](https://github.com/google/tink/tree/master/tools/tinkey), which
can be used for common key management tasks.  Moreover, there is also
[`KmsEncryptedKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KmsEncryptedKeysetHandle.java)-class,
which enables working with keysets in which the sensitive key material is
encrypted with a KMS-managed key.

Still, if there is a need to generate a KeysetHandle with fresh key material
directly in Java code, one can use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/CleartextKeysetHandle.java)-class:

``` java
    KeysetHandle keysetHandle = CleartextKeysetHandle.generateNew(keyTemplate);
```

where `keyTemplate` can be initialized with one of pre-generated templates from
[tools/tinkey/keytemplates](https://github.com/google/tink/tree/master/tools/tinkey/keytemplates)-folder.
Alternatively, one can use also
[`KeysetManager`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KeysetManager.java)-class.

## Loading Existing Keysets
Via [`KmsEncryptedKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KmsEncryptedKeysetHandle.java) or
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/CleartextKeysetHandle.java),

TODO: write more in this section

## Creating and Using a Primitive

After all needed KeyManagers have been registered, one creates a primitive
via the corresponding factory.  For example, here is how to create and use
AEAD-primitive:

``` java
    import com.google.crypto.tink.Aead;
    import com.google.crypto.tink.aead.AeadFactory;
    import com.google.crypto.tink.KeysetHandle;
    // (...)

    // 1. Get the key material.
    KeysetHandle keysetHandle = ...;
    // 2. Get the primitive.
    Aead aead = AeadFactory.getPrimitive(keysetHandle);
    // 3. Use the primitive.
    byte[] ciphertext = aead.encrypt(plaintext, aad);
```


## Key Rotation

The support for key rotation in Tink is provided via
[`KeysetManager`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KeysetManager.java)-class.
One has to provide a `KeysetHandle`-object that contains the keyset that should
be rotated, and a specification of the new key via a
[`KeyTemplate`](https://github.com/google/tink/blob/master/proto/tink.proto#L50)-message.

``` java
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeysetManager;
    import com.google.crypto.tink.proto.KeyTemplate;

    KeysetHandle keysetHandle = ...;   // existing keyset
    KeyTemplate keyTemplate = ...;     // template for the new key

    KeysetHandle rotatedKeysetHandle = new KeysetManager.Builder()
        .setKeysetHandle(keysetHandle)
        .build()
        .rotate(keyTemplate)
        .getKeysetHandle();
```

Some common specifications are available as pre-generated templates
in [examples/keytemplates](https://github.com/google/tink/tree/master/examples/keytemplates)-folder,
and can be accessed via `...KeyTemplates.java` classes of the respective
primitives.  After a successful rotation the resulting keyset contains a new key
generated according to the specification in `keyTemplate`, and the new key
becomes the _primary key_ of the keyset.  For the rotation to succeed the
`Registry` must contain a key manager for the key type specified in
`keyTemplate`.

Alternatively, one can
use [Tinkey](https://github.com/google/tink/tree/master/tools/tinkey) to rotate
a key.

TODO: write more about Tinkey

## Custom Implementation of a Primitive

**NOTE**: The usage of **custom key managers should be enjoyed
responsibly**: we (i.e. Tink developers) have no way checking or enforcing that
a custom implementation satisfies security properties of the corresponding
primitive interface, so it is up to the implementer and the user of the custom
implementation ensure the required properties.

As described in [Tink overview](../README.md#tink-overview), the main
cryptographic operations offered by Tink are accessible via so-called
_primitives_, which essentially are interfaces that represent corresponding
cryptographic functionalities.  While Tink comes with several standard
implementations of common primitives, it allows also for adding custom
implementations of primitives.  Such implementations allow for seamless
integration of Tink with custom third-party cryptographic schemes or hardware
modules, and in combination with [key rotation](#key-rotation)-features enable
painless migration between cryptographic schemes.

To create a custom implementation of a primitive proceed as follows:

1. Determine for which _primitive_ a custom implementation is needed.
2. Define protocol buffers that hold key material and parameters for the custom
   cryptographic scheme; the name of the key protocol buffer (a.k.a. type URL)
   determines the _key type_ for the custom implementation.
3. Implement [`KeyManager`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KeyManager.java) 
   interface for the _primitive_ from step #1 and the _key type_ from step #2.

To use a custom implementation of a primitive in an application, register with
the [`Registry`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/Registry.java)
the custom `KeyManager`-implementation (from step #3 above) for the custom key
type (from step #2 above):

``` java
    Registry.INSTANCE.registerKeyManager(keyType, keyManager);
```

Afterwards the implementation will be accessed automatically by the `Factory`
corresponding to the primitive (when keys of the specific key type are in use),
or can be retrieved directly via `Registry.getKeyManager(keyType)`.

When defining the protocol buffers for the key material and parameters (step #2
above), one should provide definitions of three messages:

 * `...Params`: parameters of an instantiation of the primitive,
   needed when a key is being used.
 * `...Key`: the actual key proto, contains the key material and the
   corresponding `...Params`-proto.
 * `...KeyFormat`: parameters needed to generate a new key.

Here are a few conventions/recommendations wrt. defining these messages
(see [tink.proto](https://github.com/google/tink/blob/master/proto/tink.proto)
and defintions of [existing key types](https://github.com/google/tink/blob/master/proto/)
for details):

 * `...Key` should contain a version field (a monotonic counter, `uint32 version;`),
   which identifies the version of implementation that can work with this key.
 * `...Params` should be a field of `...Key`, as by definition `...Params`
   contains parameters needed when the key is being used.
 * `...Params` should be also a field of `...KeyFormat`, so that given `...KeyFormat`
   one has all information it needs to generate a new `...Key` message.

Alternatively, depending on the use case requirements, one can skip step #2
entirely and re-use for the key material an existing protocol buffer messages.
In such a case one should not configure the Registry via the method
`registerStandardKeyTypes()` of the corresponding `Config`-class, but rather
register the needed `KeyManager`-instances manually.

For a concrete example, let's assume that we'd like a custom implementation of
[`Aead`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/Aead.java)-primitive
(step #1).  We define then three protocol buffer messages (step #2):

 * `MyCustomAeadParams`: holds parameters needed for the use of the key material.
 * `MyCustomAeadKey`: holds the actual key material and parameters needed for its use.
 * `MyCustomAeadKeyFormat`: holds parameters needed for generation of a new `MyCustomAeadKey`-key.

``` protocol-buffer
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

``` java
    String keyType = "type.googleapis.com/mycompany.mypackage.MyCustomAeadKey";`
```

and the corresponding _key manager_ implements (step #3) the interface
[`KeyManager<Aead>`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/KeyManager.java)

``` java
    class MyCustomAeadKeyManager implements KeyManager<Aead> {
      // ...
    }
```

After registering `MyCustomAeadKeyManager` with the Registry we can use it
via [`AeadFactory`](https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/aead/AeadFactory.java).


## Adding a Custom Primitive
TODO: write this section
