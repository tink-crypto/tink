// Copyright 2023 Google Inc.
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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.PrivateKey;
import com.google.crypto.tink.PrivateKeyManager;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;
import java.security.GeneralSecurityException;

/**
 * A composed KeyManager implements a KeyManager by accessing the internal specific registries.
 *
 * <p>Tink offers {@code Registry.getKeyManager} in the public API. While this shouldn't be used by
 * users, we still want to be backwards compatible for users which use it.
 *
 * <p>In this class we use the global instances of the following classes to implement the KeyManager
 * interface.
 *
 * <ul>
 *   <li>{@link MutableSerializationRegistry}
 *   <li>{@link MutablePrimitiveRegistry}
 *   <li>{@link MutableKeyCreationRegistry}
 * </ul>
 */
public class LegacyKeyManagerImpl<P> implements KeyManager<P> {
  final String typeUrl;
  final Class<P> primitiveClass;
  final KeyMaterialType keyMaterialType;
  final Parser<? extends MessageLite> protobufKeyParser;

  public static <P> KeyManager<P> create(
      String typeUrl,
      Class<P> primitiveClass,
      KeyMaterialType keyMaterialType,
      Parser<? extends MessageLite> protobufKeyParser) {
    return new LegacyKeyManagerImpl<>(typeUrl, primitiveClass, keyMaterialType, protobufKeyParser);
  }

  LegacyKeyManagerImpl(
      String typeUrl,
      Class<P> primitiveClass,
      KeyMaterialType keyMaterialType,
      Parser<? extends MessageLite> protobufKeyParser) {
    this.protobufKeyParser = protobufKeyParser;
    this.typeUrl = typeUrl;
    this.primitiveClass = primitiveClass;
    this.keyMaterialType = keyMaterialType;
  }

  @Override
  public P getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    ProtoKeySerialization serialization =
        ProtoKeySerialization.create(
            typeUrl, serializedKey, keyMaterialType, OutputPrefixType.RAW, null);
    Key key =
        MutableSerializationRegistry.globalInstance()
            .parseKey(serialization, InsecureSecretKeyAccess.get());
    return MutablePrimitiveRegistry.globalInstance().getPrimitive(key, primitiveClass);
  }

  @Override
  public final P getPrimitive(MessageLite key) throws GeneralSecurityException {
    return getPrimitive(key.toByteString());
  }

  @Override
  @SuppressWarnings("UnusedException")
  public final MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KeyData keyData = newKeyData(serializedKeyFormat);
    try {
      return protobufKeyParser.parseFrom(
          keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Unexpectedly failed to parse key");
    }
  }

  @Override
  public final MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    return newKey(keyFormat.toByteString());
  }

  @Override
  public final boolean doesSupport(String typeUrl) {
    return typeUrl.equals(getKeyType());
  }

  @Override
  public final String getKeyType() {
    return typeUrl;
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public final KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    ProtoParametersSerialization parametersSerialization =
        ProtoParametersSerialization.checkedCreate(
            KeyTemplate.newBuilder()
                .setTypeUrl(typeUrl)
                .setValue(serializedKeyFormat)
                .setOutputPrefixType(OutputPrefixType.RAW)
                .build());
    Parameters parameters =
        MutableSerializationRegistry.globalInstance().parseParameters(parametersSerialization);
    Key key =
        MutableKeyCreationRegistry.globalInstance()
            .createKey(parameters, /* idRequirement= */ null);
    ProtoKeySerialization keySerialization =
        MutableSerializationRegistry.globalInstance()
            .serializeKey(key, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
    return KeyData.newBuilder()
        .setTypeUrl(keySerialization.getTypeUrl())
        .setValue(keySerialization.getValue())
        .setKeyMaterialType(keySerialization.getKeyMaterialType())
        .build();
  }

  @Override
  public final Class<P> getPrimitiveClass() {
    return primitiveClass;
  }

  private static class LegacyPrivateKeyManagerImpl<P> extends LegacyKeyManagerImpl<P>
      implements PrivateKeyManager<P> {
    protected LegacyPrivateKeyManagerImpl(
        String typeUrl, Class<P> primitiveClass, Parser<? extends MessageLite> protobufKeyParser) {
      super(typeUrl, primitiveClass, KeyMaterialType.ASYMMETRIC_PRIVATE, protobufKeyParser);
    }

    @Override
    public KeyData getPublicKeyData(ByteString serializedKey) throws GeneralSecurityException {
      ProtoKeySerialization serialization =
          ProtoKeySerialization.create(
              typeUrl, serializedKey, keyMaterialType, OutputPrefixType.RAW, null);
      Key key =
          MutableSerializationRegistry.globalInstance()
              .parseKey(serialization, InsecureSecretKeyAccess.get());
      if (!(key instanceof PrivateKey)) {
        throw new GeneralSecurityException("Key not private key");
      }
      Key publicKey = ((PrivateKey) key).getPublicKey();
      ProtoKeySerialization publicKeySerialization =
          MutableSerializationRegistry.globalInstance()
              .serializeKey(publicKey, ProtoKeySerialization.class, InsecureSecretKeyAccess.get());
      return KeyData.newBuilder()
          .setTypeUrl(publicKeySerialization.getTypeUrl())
          .setValue(publicKeySerialization.getValue())
          .setKeyMaterialType(publicKeySerialization.getKeyMaterialType())
          .build();
    }
  }

  public static <P> PrivateKeyManager<P> createPrivateKeyManager(
      String typeUrl, Class<P> primitiveClass, Parser<? extends MessageLite> protobufKeyParser) {
    return new LegacyPrivateKeyManagerImpl<P>(typeUrl, primitiveClass, protobufKeyParser);
  }
}
