// Copyright 2020 Google LLC
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

package com.google.crypto.tink.keyderivation.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.internal.ProtoParametersSerialization;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationKey;
import com.google.crypto.tink.keyderivation.PrfBasedKeyDerivationParameters;
import com.google.crypto.tink.prf.PrfKey;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyTemplate;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.PrfBasedDeriverKey;
import com.google.crypto.tink.proto.PrfBasedDeriverKeyFormat;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * {@link com.google.crypto.tink.internal.KeyTypeManager} for {@link PrfBasedDeriverKey}.
 *
 * <p>This is implemented directly as a KeyManager. Usually, we use {@code LegacyKeyManagerImpl} to
 * provide an implementation of a KeyManager based on the individual registries based on the key
 * objects. However, at the moment for key derivation this does not work.
 *
 * <p>The reason is that the KeysetHandle still generates new keys by going through the KeyManagers
 * (instead of going directly to the key creation registry). I don't want to change this right now
 * -- it would require some fallback code which is always brittle.
 *
 * <p>Unfortunately, implement the required behavior of the KeyManager based on the KeyCreation
 * registry is not generic.
 *
 * <p>Usually, the behavior of the key manager is simply this: assume that the input to
 * generateNewKey() is a serialization with OutputPrefixType = RAW, and build the corresponding
 * parameter serialization. Then, parse this, and give this to the key creation registry.
 *
 * <p>For key creation, the behavior is slightly different: the serialization of key derivation
 * parameters has been defined to always satisfy that the outer OutputPrefixType is equal to the one
 * given in the proto PrfBasedDeriverKeyFormat, field prf_key_template. Hence we cannot assume raw
 * -- instead, we have to parse it and use this one.
 *
 * <p>Similar things hold for the creating a primitive from a Key -- but here Tink already uses the
 * PrimitiveCreationRegistry fully, so we don't need to worry about it here. Instead, we just throw
 * when these functions are called.
 */
public final class PrfBasedDeriverKeyManager implements KeyManager<Void> {
  private static final PrimitiveConstructor<PrfBasedKeyDerivationKey, KeyDeriver>
      PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              PrfBasedKeyDeriver::create, PrfBasedKeyDerivationKey.class, KeyDeriver.class);

  @AccessesPartialKey
  private static final PrfBasedKeyDerivationKey createNewKey(
      PrfBasedKeyDerivationParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    Key prfKey =
        MutableKeyCreationRegistry.globalInstance()
            .createKey(parameters.getPrfParameters(), /* idRequirement= */ null);
    if (!(prfKey instanceof PrfKey)) {
      throw new GeneralSecurityException(
          "Failed to create PrfKey from parameters"
              + parameters.getPrfParameters()
              + ", instead got "
              + prfKey.getClass());
    }
    return PrfBasedKeyDerivationKey.create(parameters, (PrfKey) prfKey, idRequirement);
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<PrfBasedKeyDerivationParameters>
      KEY_CREATOR = PrfBasedDeriverKeyManager::createNewKey;

  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";

  PrfBasedDeriverKeyManager() {}

  @Override
  public Void getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Cannot use the KeyManager to get a primitive for KeyDerivation");
  }

  @Override
  public final Void getPrimitive(MessageLite key) throws GeneralSecurityException {
    throw new GeneralSecurityException(
        "Cannot use the KeyManager to get a primitive for KeyDerivation");
  }

  @Override
  @SuppressWarnings("UnusedException")
  public final MessageLite newKey(ByteString serializedKeyFormat) throws GeneralSecurityException {
    KeyData keyData = newKeyData(serializedKeyFormat);
    try {
      return PrfBasedDeriverKey.parseFrom(
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
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return 0;
  }

  private static OutputPrefixType getOutputPrefixTypeFromSerializedKeyFormat(
      ByteString serializedKeyFormat) throws GeneralSecurityException {
    try {
      PrfBasedDeriverKeyFormat format =
          PrfBasedDeriverKeyFormat.parseFrom(
              serializedKeyFormat, ExtensionRegistryLite.getEmptyRegistry());
      return format.getParams().getDerivedKeyTemplate().getOutputPrefixType();
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Unexpectedly failed to parse key format", e);
    }
  }

  @Override
  public final KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
    OutputPrefixType outputPrefixType =
        getOutputPrefixTypeFromSerializedKeyFormat(serializedKeyFormat);
    ProtoParametersSerialization parametersSerialization =
        ProtoParametersSerialization.checkedCreate(
            KeyTemplate.newBuilder()
                .setTypeUrl(TYPE_URL)
                .setValue(serializedKeyFormat)
                .setOutputPrefixType(outputPrefixType)
                .build());
    Parameters parameters =
        MutableSerializationRegistry.globalInstance().parseParameters(parametersSerialization);
    @Nullable Integer idRequirement = null;
    if (!outputPrefixType.equals(OutputPrefixType.RAW)) {
      // The actual id requirement doesn't matter here: we just need to set something. We then
      // later serialize the generated key as KeyData (which doesn't have the ID) and then it
      // will be put into a keyset with the correct ID.
      //
      // This of course assumes that we can get a valid key by first creating one with the wrong
      // id requirement, then serializing it, and then replacing the id in the proto key
      // serialization.
      idRequirement = 123;
    }
    Key key = MutableKeyCreationRegistry.globalInstance().createKey(parameters, idRequirement);
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
  public final Class<Void> getPrimitiveClass() {
    return Void.class;
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    KeyManagerRegistry.globalInstance()
        .registerKeyManager(new PrfBasedDeriverKeyManager(), newKeyAllowed);
    MutableKeyCreationRegistry.globalInstance()
        .add(KEY_CREATOR, PrfBasedKeyDerivationParameters.class);
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(PRIMITIVE_CONSTRUCTOR);

    PrfBasedKeyDerivationKeyProtoSerialization.register();
  }
}
