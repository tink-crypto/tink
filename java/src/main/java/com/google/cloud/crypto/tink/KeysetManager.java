// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package com.google.cloud.crypto.tink;

import com.google.cloud.crypto.tink.TinkProto.KeyData;
import com.google.cloud.crypto.tink.TinkProto.KeyStatusType;
import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.TinkProto.Keyset;
import com.google.cloud.crypto.tink.TinkProto.OutputPrefixType;
import com.google.cloud.crypto.tink.subtle.Random;
import com.google.common.collect.ImmutableSet;
import com.google.common.reflect.ClassPath;
import com.google.common.reflect.ClassPath.ClassInfo;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;

/**
 * Manages a Keyset-proto, with convenience methods that rotate, disable, enable or
 * destroy keys.
 * Not thread-safe.
 */
public class KeysetManager {
  private final Keyset.Builder keysetBuilder;
  private final KeyTemplate keyTemplate;
  private final OutputPrefixType outputPrefixType;

  private KeysetManager(Builder builder) {
    keyTemplate = builder.keyTemplate;
    outputPrefixType = builder.outputPrefixType;

    if (builder.keysetHandle != null) {
      keysetBuilder = builder.keysetHandle.getKeyset().toBuilder();
    } else {
      keysetBuilder = Keyset.newBuilder();
    }
  }

  /**
   * Builder for KeysetManager.
   */
  public static class Builder {
    private OutputPrefixType outputPrefixType = OutputPrefixType.TINK;
    private KeyTemplate keyTemplate = null;
    private KeysetHandle keysetHandle = null;

    public Builder() {
    }


    public Builder setOutputPrefixType(OutputPrefixType val) {
      outputPrefixType = val;
      return this;
    }

    public Builder setKeysetHandle(KeysetHandle val) {
      keysetHandle = val;
      return this;
    }

    public Builder setKeyTemplate(KeyTemplate val) {
      keyTemplate = val;
      return this;
    }

    public KeysetManager build() {
      return new KeysetManager(this);
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using a key template.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate() throws GeneralSecurityException {
    if (keyTemplate != null) {
      return rotate(keyTemplate);
    } else {
      throw new GeneralSecurityException("cannot rotate, needs key template");
    }
  }

  /**
   * Rotates a keyset by generating a fresh key using {@code keyTemplate}.
   * Setting the new key as the primary key.
   */
  public KeysetManager rotate(KeyTemplate keyTemplate) throws GeneralSecurityException {
    KeyData keyData = Registry.INSTANCE.newKeyData(keyTemplate);
    int keyId = Random.randPositiveInt();
    while (hasKeyWithKeyId(keyId)) {
      keyId = Random.randPositiveInt();
    }
    Keyset.Key key = Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setKeyId(keyId)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(outputPrefixType)
        .build();
    keysetBuilder.addKey(key).setPrimaryKeyId(key.getKeyId());
    return this;
  }

  /**
   * Transforms all private keys in the keyset to public keys.
   * Warning: the private keys are destroyed if the operation is successful.
   * @throws GeneralSecurityException if cannot convert one of the keys or cannot find
   * the corresponding public key protobuf.
   */
  public KeysetManager transformToPublicKeyset() throws GeneralSecurityException {
    Keyset.Builder keysetBuilder2 = Keyset.newBuilder();
    for (Keyset.Key key : keysetBuilder.getKeyList()) {
      KeyData keyData = createPublicKeyData(key.getKeyData());
      keysetBuilder2.addKey(Keyset.Key.newBuilder()
          .mergeFrom(key)
          .setKeyData(keyData)
          .build());
    }
    keysetBuilder.clearKey();
    keysetBuilder.mergeFrom(keysetBuilder2.build());
    return this;
  }

  /**
   * @return return {@code KeysetHandle} of the managed keyset.
   */
  public KeysetHandle getKeysetHandle() {
    return new KeysetHandle(keysetBuilder.build());
  }

  /**
   * Encrypts the managed keyset with {@code aead} and returns a {@code KeysetHandle} of
   * the encrypted result.
   * @return a {@code KeysetHandle} of an encrypted keyset.
   * @throws GeneralSecurityException
   */
  public KeysetHandle getKeysetHandle(Aead aead) throws GeneralSecurityException {
    Keyset keyset = keysetBuilder.build();
    byte[] encryptedKeyset = aead.encrypt(keyset.toByteArray(), new byte[0] /* aad */);
    // Check if we can decrypt encryptedKeyset, to detect errors
    try {
      byte[] cleartext = aead.decrypt(encryptedKeyset, new byte[0] /* aad */);
      Keyset keyset2 = Keyset.parseFrom(cleartext);
      if (!keyset2.equals(keyset)) {
        throw new GeneralSecurityException("encryption with KMS failed");
      }
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("encryption with KMS failed");
    }

    return new KeysetHandle(keyset, encryptedKeyset);
  }

  private boolean hasKeyWithKeyId(int keyId) {
    for (Keyset.Key key : keysetBuilder.getKeyList()) {
      if (key.getKeyId() == keyId) {
        return true;
      }
    }
    return false;
  }

  private static KeyData createPublicKeyData(KeyData privateKeyData)
      throws GeneralSecurityException {
    if (privateKeyData.getKeyMaterialType() != KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE) {
      throw new GeneralSecurityException("The keyset contains non-private key");
    }
    KeyData publicKeyData = getPublicKeyData(privateKeyData);
    validate(publicKeyData);
    return publicKeyData;
  }

  private static KeyData getPublicKeyData(KeyData privateKeyData)
      throws GeneralSecurityException {
    String className = getClassNameFromTypeUrl(privateKeyData.getTypeUrl());
    Class<?> privateKeyProtoClass = loadClass(className);
    try {
      Object privateKeyInstance = privateKeyProtoClass
          .getDeclaredMethod("parseFrom", ByteString.class)
          .invoke(null /* Object, ignored */, privateKeyData.getValue());
      MessageLite publicKey = (MessageLite) privateKeyProtoClass
          .getDeclaredMethod("getPublicKey")
          .invoke(privateKeyInstance);
      return KeyData.newBuilder()
          .setTypeUrl(getPublicKeyTypeUrl(privateKeyData.getTypeUrl()))
          .setValue(publicKey.toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } catch (Exception e) {
      throw new GeneralSecurityException("Cannot extract public key", e);
    }
  }

  private static void validate(KeyData keyData) throws GeneralSecurityException {
    // This will throw GeneralSecurityException if the keyData is invalid.
    Registry.INSTANCE.getPrimitive(keyData);
  }

  private static String getClassNameFromTypeUrl(String typeUrl) {
    int dot = typeUrl.lastIndexOf(".");
    return typeUrl.substring(dot + 1);
  }

  private static String getPublicKeyTypeUrl(String privateKeyTypeUrl) {
    return privateKeyTypeUrl.replace("PrivateKey", "PublicKey");
  }

  private static Class<?> loadClass(String className) throws GeneralSecurityException {
    try {
      ImmutableSet<ClassInfo> classInfos =
          ClassPath.from(KeysetManager.class.getClassLoader()).getAllClasses();
      for (ClassInfo classInfo : classInfos) {
        if (classInfo.getName().toLowerCase().endsWith(className.toLowerCase())) {
          return classInfo.load();
        }
      }
    } catch (Exception e) {
      throw new GeneralSecurityException("Class not found: " + className, e);
    }
    throw new GeneralSecurityException("Class not found: " + className);
  }
}
