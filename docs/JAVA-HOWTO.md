# Tink for Java HOW-TO

This document contains instructions and Java code snippets for common tasks in
[Tink](https://github.com/google/tink).

If you want to contribute code to the Java implementation, please read the [Java
hacking guide](JAVA-HACKING.md).

## Setup instructions

The most recent release is
[1.6.0](https://github.com/google/tink/releases/tag/v1.6.0), released
2021-04-29.

In addition to the versioned releases, snapshots of Tink are regularly built
using the master branch of the Tink GitHub repository.

Tink for Java has two primary build targets specified:

- "tink": the default, for general purpose use
- "android": which is optimized for use in Android projects

### Maven

You can can include Tink in Java projects projects using
[Maven](https://maven.apache.org/).

The Maven group ID is `com.google.crypto.tink`, and the artifact ID is `tink`.

You can specify the current release of Tink as a project dependency using the
following configuration:

```xml
<dependencies>
  <dependency>
    <groupId>com.google.crypto.tink</groupId>
    <artifactId>tink</artifactId>
    <version>1.6.0</version>
  </dependency>
</dependencies>
```

You can specify the latest snapshot as a project dependency by using the version
`HEAD-SNAPSHOT`:

```xml
<repositories>
  <repository>
    <id>sonatype-snapshots</id>
    <name>sonatype-snapshots</name>
    <url>https://oss.sonatype.org/content/repositories/snapshots/</url>
    <snapshots>
      <enabled>true</enabled>
      <updatePolicy>always</updatePolicy>
    </snapshots>
    <releases>
      <updatePolicy>always</updatePolicy>
    </releases>
  </repository>
</repositories>

...

<dependencies>
  <dependency>
    <groupId>com.google.crypto.tink</groupId>
    <artifactId>tink</artifactId>
    <version>HEAD-SNAPSHOT</version>
  </dependency>
</dependencies>
```

### AWS/GCP integration

Since 1.3.0 the support for AWS/GCP KMS has been moved to a separate package. To
use AWS KMS, one should also add dependency on `tink-awskms`, and similarly
`tink-gcpkms` for GCP KMS.

```xml
<dependencies>
  <dependency>
    <groupId>com.google.crypto.tink</groupId>
    <artifactId>tink-awskms</artifactId>
    <version>1.5.0</version>
  </dependency>
</dependencies>
```

```xml
<dependencies>
  <dependency>
    <groupId>com.google.crypto.tink</groupId>
    <artifactId>tink-gcpkms</artifactId>
    <version>1.5.0</version>
  </dependency>
</dependencies>
```

### Gradle

You can include Tink in Android projects using [Gradle](https://gradle.org).

You can specify the current release of Tink as a project dependency using the
following configuration:

```
dependencies {
  implementation 'com.google.crypto.tink:tink-android:1.5.0'
}
```

You can specify the latest snapshot as a project dependency using the following
configuration:

```
repositories {
    maven { url "https://oss.sonatype.org/content/repositories/snapshots" }
}

dependencies {
  implementation 'com.google.crypto.tink:tink-android:HEAD-SNAPSHOT'
}
```

## API documentation

*   Java:
    *   [1.5.0](https://google.github.io/tink/javadoc/tink/1.5.0)
    *   [HEAD-SNAPSHOT](https://google.github.io/tink/javadoc/tink/HEAD-SNAPSHOT)
*   Android:
    *   [1.5.0](https://google.github.io/tink/javadoc/tink-android/1.5.0)
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
[`KeysetHandle`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/KeysetHandle.java).
For example, you can generate a keyset containing a randomly generated
AES128-GCM key as follows.

```java
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.KeysetHandle;

    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES128_GCM"));
```

## Storing keysets

After generating key material, you might want to persist it to a storage system,
e.g., writing to a file:

```java
    import com.google.crypto.tink.CleartextKeysetHandle;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.JsonKeysetWriter;
    import java.io.File;

    // Generate the key material...
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES128_GCM"));

    // and write it to a file.
    String keysetFilename = "my_keyset.json";
    CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withFile(
        new File(keysetFilename)));
```

Storing cleartext keysets on disk is not recommended. Tink supports encrypting
keysets with master keys stored in remote [key management
systems](KEY-MANAGEMENT.md).

For example, you can encrypt the key material with a key stored in Google Cloud
KMS key as follows:

```java
    import com.google.crypto.tink.JsonKeysetWriter;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.integration.gcpkms.GcpKmsClient;
    import java.io.File;

    // Generate the key material...
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES128_GCM"));

    // and write it to a file...
    String keysetFilename = "my_keyset.json";
    // encrypted with the this key in GCP KMS
    String masterKeyUri = "gcp-kms://projects/tink-examples/locations/global/keyRings/foo/cryptoKeys/bar";
    keysetHandle.write(JsonKeysetWriter.withFile(new File(keysetFilename)),
        new GcpKmsClient().getAead(masterKeyUri));
```

## Loading existing keysets

To load encrypted keysets, use
[`KeysetHandle`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/KeysetHandle.java):

```java
    import com.google.crypto.tink.JsonKeysetReader;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.integration.awskms.AwsKmsClient;
    import java.io.File;

    String keysetFilename = "my_keyset.json";
    // The keyset is encrypted with the this key in AWS KMS.
    String masterKeyUri = "aws-kms://arn:aws:kms:us-east-1:007084425826:key/84a65985-f868-4bfc-83c2-366618acf147";
    KeysetHandle keysetHandle = KeysetHandle.read(
        JsonKeysetReader.withFile(new File(keysetFilename)),
        new AwsKmsClient().getAead(masterKeyUri));
```

To load cleartext keysets, use
[`CleartextKeysetHandle`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/CleartextKeysetHandle.java):

```java
    import com.google.crypto.tink.CleartextKeysetHandle;
    import com.google.crypto.tink.KeysetHandle;
    import java.io.File;

    String keysetFilename = "my_keyset.json";
    KeysetHandle keysetHandle = CleartextKeysetHandle.read(
        JsonKeysetReader.withFile(new File(keysetFilename)));
```

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
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES128_GCM"));

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
    import com.google.crypto.tink.DeterministicAead;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES256_SIV"));

    // 2. Get the primitive.
    DeterministicAead daead =
       keysetHandle.getPrimitive(DeterministicAead.class);

    // 3. Use the primitive to deterministically encrypt a plaintext,
    byte[] ciphertext = daead.encryptDeterministically(plaintext, aad);

    // ... or to deterministically decrypt a ciphertext.
    byte[] decrypted = daead.decryptDeterministically(ciphertext, aad);
```

### Symmetric key encryption of streaming data

You can obtain and use a
[Streaming AEAD](PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data)
(Streaming Authenticated Encryption with Associated Data) primitive to encrypt
or decrypt data streams:

```java
    import com.google.crypto.tink.StreamingAead;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;
    import java.nio.ByteBuffer;
    import java.nio.channels.FileChannel;
    import java.nio.channels.SeekableByteChannel;
    import java.nio.channels.WritableByteChannel;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("AES128_GCM_HKDF_1MB"));

    // 2. Get the primitive.
    StreamingAead streamingAead = keysetHandle.getPrimitive(StreamingAead.class);

    // 3. Use the primitive to encrypt some data and write the ciphertext to a file,
    FileChannel ciphertextDestination =
        new FileOutputStream(ciphertextFileName).getChannel();
    byte[] aad = ...
    WritableByteChannel encryptingChannel =
        streamingAead.newEncryptingChannel(ciphertextDestination, aad);
    ByteBuffer buffer = ByteBuffer.allocate(chunkSize);
    while ( bufferContainsDataToEncrypt ) {
      int r = encryptingChannel.write(buffer);
      // Try to get into buffer more data for encryption.
    }
    // Complete the encryption (process the remaining plaintext, if any, and close the channel).
    encryptingChannel.close();

    // ... or to decrypt an existing ciphertext stream.
    FileChannel ciphertextSource =
        new FileInputStream(ciphertextFileName).getChannel();
    byte[] aad = ...
    ReadableByteChannel decryptingChannel =
        s.newDecryptingChannel(ciphertextSource, aad);
    ByteBuffer buffer = ByteBuffer.allocate(chunkSize);
    do {
      buffer.clear();
      int cnt = decryptingChannel.read(buffer);
      if (cnt > 0) {
        // Process cnt bytes of plaintext.
      } else if (read == -1) {
        // End of plaintext detected.
        break;
      } else if (read == 0) {
        // No ciphertext is available at the moment.
      }
   }
```

### Message Authentication Code

You can compute or verify a [MAC](PRIMITIVES.md#message-authentication-code)
(Message Authentication Code):

```java
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.Mac;

    // 1. Generate the key material.
    KeysetHandle keysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("HMAC_SHA256_128BITTAG"));

    // 2. Get the primitive.
    Mac mac = keysetHandle.getPrimitive(Mac.class);

    // 3. Use the primitive to compute a tag,
    byte[] tag = mac.computeMac(data);

    // ... or to verify a tag.
    mac.verifyMac(tag, data);
```

### Digital signatures

You can sign or verify a [digital
signature](PRIMITIVES.md#digital-signatures):

```java
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.PublicKeySign;
    import com.google.crypto.tink.PublicKeyVerify;

    // SIGNING

    // 1. Generate the private key material.
    KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("ECDSA_P256"));

    // 2. Get the primitive.
    PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);

    // 3. Use the primitive to sign.
    byte[] signature = signer.sign(data);

    // VERIFYING

    // 1. Obtain a handle for the public key material.
    KeysetHandle publicKeysetHandle =
        privateKeysetHandle.getPublicKeysetHandle();

    // 2. Get the primitive.
    PublicKeyVerify verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify.class);

    // 4. Use the primitive to verify.
    verifier.verify(signature, data);
```

### Hybrid encryption

To encrypt or decrypt using [a combination of public key encryption and
symmetric key encryption](PRIMITIVES.md#hybrid-encryption) one can
use the following:

```java
    import com.google.crypto.tink.HybridDecrypt;
    import com.google.crypto.tink.HybridEncrypt;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeyTemplates;

    // 1. Generate the private key material.
    KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(
        KeyTemplates.get("ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM"));

    // Obtain the public key material.
    KeysetHandle publicKeysetHandle =
        privateKeysetHandle.getPublicKeysetHandle();

    // ENCRYPTING

    // 2. Get the primitive.
    HybridEncrypt hybridEncrypt =
        publicKeysetHandle.getPrimitive(HybridEncrypt.class);

    // 3. Use the primitive.
    byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);

    // DECRYPTING

    // 2. Get the primitive.
    HybridDecrypt hybridDecrypt = privateKeysetHandle.getPrimitive(
        HybridDecrypt.class);

    // 3. Use the primitive.
    byte[] plaintext = hybridDecrypt.decrypt(ciphertext, contextInfo);
```

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
[`KeysetManager`](https://github.com/google/tink/blob/master/java_src/src/main/java/com/google/crypto/tink/KeysetManager.java)
class.

You have to provide a `KeysetHandle`-object that contains the keyset that should
be rotated, and a specification of the new key via a
[`KeyTemplate`](https://github.com/google/tink/blob/master/proto/tink.proto#L50)
message.

```java
    import com.google.crypto.tink.KeyTemplate;
    import com.google.crypto.tink.KeyTemplates;
    import com.google.crypto.tink.KeysetHandle;
    import com.google.crypto.tink.KeysetManager;

    KeysetHandle keysetHandle = ...;   // existing keyset
    KeyTemplate keyTemplate = KeyTemplates.get("AES256_GCM"); // template for the new key

    KeysetHandle rotatedKeysetHandle = KeysetManager
        .withKeysetHandle(keysetHandle)
        .rotate(keyTemplate)
        .getKeysetHandle();
```

After a successful rotation, the resulting keyset contains a new key generated
according to the specification in `keyTemplate`, and the new key becomes the
_primary key_ of the keyset.  For the rotation to succeed the `Registry` must
contain a key manager for the key type specified in `keyTemplate`.

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
