# Message Encryption for Web Push

This Tink app is an implementation of [RFC 8291 - Message Encryption for Web
Push](https://tools.ietf.org/html/rfc8291).

The most recent release is
[1.7.0](https://github.com/google/tink/releases/tag/v1.7.0), released
2022-08-09. API docs can be found
[here](https://google.github.io/tink/javadoc/apps-webpush/1.7.0).

## Installation

To add a dependency using Maven:

```xml
<dependency>
  <groupId>com.google.crypto.tink</groupId>
  <artifactId>apps-webpush</artifactId>
  <version>1.7.0</version>
</dependency>
```

To add a dependency using Gradle:

```
dependencies {
  implementation 'com.google.crypto.tink:apps-webpush:1.7.0'
}
```

## Encryption

```java
import com.google.crypto.tink.HybridEncrypt;
import java.security.interfaces.ECPublicKey;

ECPublicKey reicipientPublicKey = ...;
byte[] authSecret = ...;
HybridEncrypt hybridEncrypt = new WebPushHybridEncrypt.Builder()
     .withAuthSecret(authSecret)
     .withRecipientPublicKey(recipientPublicKey)
     .build();
byte[] plaintext = ...;
byte[] ciphertext = hybridEncrypt.encrypt(plaintext, null /* contextInfo, must be null */);
```

## Decryption

```java
import com.google.crypto.tink.HybridDecrypt;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

ECPrivateKey recipientPrivateKey = ...;
ECPublicKey  recipientPublicKey = ...;
HybridDecrypt hybridDecrypt = new WebPushHybridDecrypt.Builder()
     .withAuthSecret(authSecret)
     .withRecipientPublicKey(recipientPublicKey)
     .withRecipientPrivateKey(recipientPrivateKey)
     .build();
byte[] ciphertext = ...;
byte[] plaintext = hybridDecrypt.decrypt(ciphertext, /* contextInfo, must be null */);
```
