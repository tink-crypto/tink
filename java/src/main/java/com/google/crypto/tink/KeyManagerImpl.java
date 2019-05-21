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

package com.google.crypto.tink;

import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;

/** Implementation of the {@link KeyManager} interface based on an {@link InternalKeyManager}. */
@Alpha
class KeyManagerImpl<PrimitiveT, KeyProtoT extends MessageLite> implements KeyManager<PrimitiveT> {
  public KeyManagerImpl(
      InternalKeyManager<KeyProtoT> internalKeyManager, Class<PrimitiveT> primitiveClass) {
    if (!internalKeyManager.supportedPrimitives().contains(primitiveClass)) {
      throw new IllegalArgumentException(
          String.format(
              "Given internalKeyMananger %s does not support primitive class %s",
              internalKeyManager.toString(), primitiveClass.getName()));
    }
    this.internalKeyManager = internalKeyManager;
    this.primitiveClass = primitiveClass;
  }

  private final InternalKeyManager<KeyProtoT> internalKeyManager;
  private final Class<PrimitiveT> primitiveClass;

  private static <CastedT> CastedT castOrThrowSecurityException(
      Object objectToCast, String exceptionText, Class<CastedT> classObject)
      throws GeneralSecurityException {
    if (!classObject.isInstance(objectToCast)) {
      throw new GeneralSecurityException(exceptionText);
    }
    @SuppressWarnings("unchecked")
    CastedT result = (CastedT) objectToCast;
    return result;
  }

  @Override
  public final PrimitiveT getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    try {
      KeyProtoT keyProto = internalKeyManager.parseKey(serializedKey);
      return validateKeyAndGetPrimitive(keyProto);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "Failures parsing proto of type " + internalKeyManager.getKeyClass().getName(), e);
    }
  }

  @Override
  public final PrimitiveT getPrimitive(MessageLite key) throws GeneralSecurityException {
    return validateKeyAndGetPrimitive(
        castOrThrowSecurityException(
            key,
            "Expected proto of type " + internalKeyManager.getKeyClass().getName(),
            internalKeyManager.getKeyClass()));
  }

  @Override
  public final MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      return keyFactoryHelper().parseValidateCreate(serializedKeyFormat);
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException(
          "Failures parsing proto of type "
              + internalKeyManager.keyFactory().getKeyFormatClass().getName(),
          e);
    }
  }

  @Override
  public final MessageLite newKey(MessageLite keyFormat) throws GeneralSecurityException {
    return keyFactoryHelper().castValidateCreate(keyFormat);
  }

  @Override
  public final boolean doesSupport(String typeUrl) {
    return typeUrl.equals(getKeyType());
  }

  @Override
  public final String getKeyType() {
    return internalKeyManager.getKeyType();
  }

  @Override
  public int getVersion() {
    return internalKeyManager.getVersion();
  }

  @Override
  public final KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      KeyProtoT key = keyFactoryHelper().parseValidateCreate(serializedKeyFormat);
      return KeyData.newBuilder()
          .setTypeUrl(getKeyType())
          .setValue(key.toByteString())
          .setKeyMaterialType(internalKeyManager.keyMaterialType())
          .build();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Unexpected proto", e);
    }
  }

  @Override
  public final Class<PrimitiveT> getPrimitiveClass() {
    return primitiveClass;
  }

  private PrimitiveT validateKeyAndGetPrimitive(KeyProtoT keyProto)
      throws GeneralSecurityException {
    internalKeyManager.validateKey(keyProto);
    return internalKeyManager.getPrimitive(keyProto, primitiveClass);
  }

  /**
   * A helper class which exposes functions bundling multiple functions of the given {@link
   * InternalKeyManager.KeyFactory}.
   *
   * <p>The KeyFactory uses generics. By bundling functions in a class which uses the same generics
   * we can refer to the types in code.
   */
  private static class KeyFactoryHelper<
      KeyFormatProtoT extends MessageLite, KeyProtoT extends MessageLite> {
    KeyFactoryHelper(InternalKeyManager.KeyFactory<KeyFormatProtoT, KeyProtoT> keyFactory) {
      this.keyFactory = keyFactory;
    }

    final InternalKeyManager.KeyFactory<KeyFormatProtoT, KeyProtoT> keyFactory;

    private KeyProtoT validateCreate(KeyFormatProtoT keyFormat) throws GeneralSecurityException {
      keyFactory.validateKeyFormat(keyFormat);
      return keyFactory.createKey(keyFormat);
    }

    KeyProtoT parseValidateCreate(ByteString serializedKeyFormat)
        throws GeneralSecurityException, InvalidProtocolBufferException {
      return validateCreate(keyFactory.parseKeyFormat(serializedKeyFormat));
    }

    KeyProtoT castValidateCreate(MessageLite message) throws GeneralSecurityException {
      return validateCreate(
          castOrThrowSecurityException(
              message,
              "Expected proto of type " + keyFactory.getKeyFormatClass().getName(),
              keyFactory.getKeyFormatClass()));
    }
  }

  private KeyFactoryHelper<?, KeyProtoT> keyFactoryHelper() {
    return new KeyFactoryHelper<>(internalKeyManager.keyFactory());
  }
}
