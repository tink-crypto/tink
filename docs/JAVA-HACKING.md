# Hacking Tink for Java and Android

## Building Tink

*   Install [Bazel](https://docs.bazel.build/versions/master/install.html).

*   To build Java, install Android SDK 23 or newer and set the ANDROID_HOME
    environment variable to the path of your Android SDK. On macOS, the SDK is
    usually installed at `/Users/username/Library/Android/sdk/`. You also need
    Android SDK Build Tools 24.0.3 or newer.

*   The javadoc targets require using JDK 8.

*   Check out the source code, navigate to the Java Bazel workspace and execute
    all test targets in the project:

```shell
git clone https://github.com/google/tink
cd tink/java_src
bazel test ...
```

## Code structure

### Java packages

*   **com.google.crypto.tink** This package consists of only the core of Tink,
    including the primitive interfaces and key management APIs. Users that
    [develop their own primitives or key
    types](JAVA-HOWTO.md#custom-implementation-of-a-primitive)
    can depend only on this package and exclude the rest.

    *   internal dependencies: none
    *   external dependencies
        *   com.google.protobuf.ByteString
        *   com.google.protobuf.MessageLite
        *   javax.annotation.concurrent.GuardedBy
        *   com.google.gson.JsonArray;
        *   com.google.gson.JsonObject;
        *   com.google.gson.JsonParseException;
        *   com.google.gson.JsonParser;
        *   com.google.gson.internal.Streams;
        *   com.google.gson.stream.JsonReader;
    *   API backward-compatibility guarantee: yes

*   **com.google.crypto.tink.aead|daead|mac|signature|hybrid|streamingaead**
    These packages contain the public APIs exposing the primitives that Tink
    supports.

    *   internal dependencies
        *   com.google.crypto.tink
        *   com.google.crypto.tink.subtle
        *   com.google.crypto.tink.proto
    *   external dependencies
        *   com.google.protobuf.ByteString
        *   com.google.protobuf.MessageLite
        *   javax.annotation.concurrent.GuardedBy
    *   API backward-compatibility guarantee: yes

*   **com.google.crypto.tink.integration.gcpkms** This package allows users to
    store keys in [Google Cloud Key Management
    System](https://cloud.google.com/kms/).

    *   internal dependencies
        *   com.google.crypto.tink
        *   com.google.crypto.tink.subtle
    *   external dependencies
        *   com.google.api.services.cloudkms.v1
        *   com.google.api.client.googleapis.auth.oauth2.GoogleCredential
        *   com.google.api.client.http.javanet.NetHttpTransport
        *   com.google.api.client.json.jackson2.JacksonFactory
        *   com.google.auto.service.AutoService
    *   API backward-compatibility guarantee: yes

*   **com.google.crypto.tink.integration.awskms** This package allows users to
    store keys in [AWS Key Management System](https://aws.amazon.com/kms/).

    *   internal dependencies
        *   com.google.crypto.tink
        *   com.google.crypto.tink.subtle
    *   external dependencies
        *   com.amazonaws.AmazonServiceException
        *   com.amazonaws.auth.AWSCredentialsProvider
        *   com.amazonaws.auth.DefaultAWSCredentialsProviderChain
        *   com.amazonaws.auth.PropertiesFileCredentialsProvider
        *   com.amazonaws.services.kms
        *   com.google.auto.service.AutoService
    *   API backward-compatibility guarantee: yes

*   **com.google.crypto.tink.integration.android** This package allows Android
    users to store keys in private preferences, wrapped with master key in
    [Android
    Keystore](https://developer.android.com/training/articles/keystore.html).
    The integration with Android Keystore only works on Android M (API level 23)
    or higher.

    *   internal dependencies
        *   com.google.crypto.tink
        *   com.google.crypto.tink.subtle
    *   external dependencies
        *   Android SDK 23 or higher
    *   API backward-compatibility guarantee: yes

*   **com.google.crypto.tink.subtle** This package contains implementations of
    primitives. Aside from the primitive interfaces, this package is not allowed
    to depend on anything else in Tink. Users should never directly depend on
    this package.

    *   internal dependencies
        *   com.google.crypto.tink.Aead
        *   com.google.crypto.tink.DeterministicAead
        *   com.google.crypto.tink.HybridDecrypt
        *   com.google.crypto.tink.HybridEncrypt
        *   com.google.crypto.tink.Mac
        *   com.google.crypto.tink.StreamingAead
        *   com.google.crypto.tink.PublicKeySign
        *   com.google.crypto.tink.PublicKeyVerify
    *   external dependencies
        *   javax.annotation.concurrent.GuardedBy
    *   API backward-compatibility guarantee: no

*   **com.google.crypto.tink.proto** This package contains protobuf
    auto-generated Java code. Users should never directly depend on this
    package.

    *   internal dependencies: none
    *   external dependencies: none
    *   API backward-compatibility guarantee: no

### Bazel targets

*   **//java** This public target exports all public APIs, except
    com.google.crypto.tink.integration.android and
    com.google.crypto.tink.CleartextKeysetHandle. It is expected to run on
    servers, not Android.

*   **//java:android** Similar to java, but this public target adds
    com.google.crypto.tink.integration.android, and removes
    com.google.crypto.tink.integration.gcpkms and
    com.google.crypto.tink.integration.awskms. To build it, one needs Android
    SDK 23 or newer.

*   **//java:subtle** This restricted target exposes
    com.google.crypto.tink.subtle. It's restricted because most users are
    supposed not to use it directly.

*   **//java:cleartext_keyset_handle** and
    **//java:cleartext_keyset_handle_android** This restricted target exposes
    com.google.crypto.tink.CleartextKeysetHandle. It's restricted because it
    allows users to read cleartext keysets from disk, which is a bad practice.

*   **//java:protos** and **//java:protos_android** This restricted target
    exposes com.google.crypto.tink.proto. It's restricted because most users are
    supposed not to use it directly.

### Maven jars

*   **[com.google.crypto.tink:tink](https://mvnrepository.com/artifact/com.google.crypto.tink/tink)**
    includes //java and //java:cleartext_keyset_handle.

*   **[com.google.crypto.tink:tink-android](https://mvnrepository.com/artifact/com.google.crypto.tink/tink-android)**
    includes //java:android and //java:cleartext_keyset_handle_android
