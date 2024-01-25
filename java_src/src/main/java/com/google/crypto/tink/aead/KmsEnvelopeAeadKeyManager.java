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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.TinkProtoParametersFormat;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances of
 * {@code KmsEnvelopeAead}.
 */
public class KmsEnvelopeAeadKeyManager {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.KmsEnvelopeAeadKey.parser());

  /**
   * Creates a "new" key from a parameters.
   *
   * <p>While this creates a new Key object, it doesn't actually create a new key. It simply creates
   * the key object corresponding to this parameters object. Creating a new key would require to
   * call an API in the KMS, which this method does not do.
   *
   * <p>The reason this method exists is that in the past, Tink did not provide an API for the user
   * to create a key object by themselves. Instead, users had to always create a Key from a key
   * template (which is now a Parameters object) via {@code KeysetHandle.generateNew(template);}. To
   * support old usages, we need to register this creator.
   */
  @AccessesPartialKey
  private static LegacyKmsEnvelopeAeadKey newKey(
      LegacyKmsEnvelopeAeadParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException(
          "Id Requirement is not supported for LegacyKmsEnvelopeAeadKey");
    }
    return LegacyKmsEnvelopeAeadKey.create(parameters);
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<LegacyKmsEnvelopeAeadParameters>
      KEY_CREATOR = KmsEnvelopeAeadKeyManager::newKey;

  @AccessesPartialKey
  private static Aead create(LegacyKmsEnvelopeAeadKey key) throws GeneralSecurityException {
    byte[] serializedDekParameters =
        TinkProtoParametersFormat.serialize(key.getParameters().getDekParametersForNewKeys());
    com.google.crypto.tink.proto.KeyTemplate dekKeyTemplate;
    try {
      dekKeyTemplate =
          com.google.crypto.tink.proto.KeyTemplate.parseFrom(
              serializedDekParameters, ExtensionRegistryLite.getEmptyRegistry());
    } catch (InvalidProtocolBufferException e) {
      throw new GeneralSecurityException("Parsing of DEK key template failed: ", e);
    }
    String kekUri = key.getParameters().getKekUri();
    return new KmsEnvelopeAead(dekKeyTemplate, KmsClients.get(kekUri).getAead(kekUri));
  }

  private static final PrimitiveConstructor<LegacyKmsEnvelopeAeadKey, Aead>
      LEGACY_KMS_ENVELOPE_AEAD_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              KmsEnvelopeAeadKeyManager::create, LegacyKmsEnvelopeAeadKey.class, Aead.class);

  static String getKeyType() {
    return TYPE_URL;
  }

  private static AeadParameters makeRawAesGcm(AesGcmParameters parameters)
      throws GeneralSecurityException {
    return AesGcmParameters.builder()
        .setIvSizeBytes(parameters.getIvSizeBytes())
        .setKeySizeBytes(parameters.getKeySizeBytes())
        .setTagSizeBytes(parameters.getTagSizeBytes())
        .setVariant(AesGcmParameters.Variant.NO_PREFIX)
        .build();
  }

  private static AeadParameters makeRawChaCha20Poly1305() {
    return ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX);
  }

  private static AeadParameters makeRawXChaCha20Poly1305() {
    return XChaCha20Poly1305Parameters.create(XChaCha20Poly1305Parameters.Variant.NO_PREFIX);
  }

  private static AeadParameters makeRawAesCtrHmacAead(AesCtrHmacAeadParameters parameters)
      throws GeneralSecurityException {
    return AesCtrHmacAeadParameters.builder()
        .setAesKeySizeBytes(parameters.getAesKeySizeBytes())
        .setHmacKeySizeBytes(parameters.getHmacKeySizeBytes())
        .setTagSizeBytes(parameters.getTagSizeBytes())
        .setIvSizeBytes(parameters.getIvSizeBytes())
        .setHashType(parameters.getHashType())
        .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
        .build();
  }

  private static AeadParameters makeRawAesEax(AesEaxParameters parameters)
      throws GeneralSecurityException {
    return AesEaxParameters.builder()
        .setIvSizeBytes(parameters.getIvSizeBytes())
        .setKeySizeBytes(parameters.getKeySizeBytes())
        .setTagSizeBytes(parameters.getTagSizeBytes())
        .setVariant(AesEaxParameters.Variant.NO_PREFIX)
        .build();
  }

  private static AeadParameters makeRawAesGcmSiv(AesGcmSivParameters parameters)
      throws GeneralSecurityException {
    return AesGcmSivParameters.builder()
        .setKeySizeBytes(parameters.getKeySizeBytes())
        .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
        .build();
  }

  private static AeadParameters makeRaw(Parameters parameters) throws GeneralSecurityException {
    if (parameters instanceof AesGcmParameters) {
      return makeRawAesGcm((AesGcmParameters) parameters);
    }
    if (parameters instanceof ChaCha20Poly1305Parameters) {
      return makeRawChaCha20Poly1305();
    }
    if (parameters instanceof XChaCha20Poly1305Parameters) {
      return makeRawXChaCha20Poly1305();
    }
    if (parameters instanceof AesCtrHmacAeadParameters) {
      return makeRawAesCtrHmacAead((AesCtrHmacAeadParameters) parameters);
    }
    if (parameters instanceof AesEaxParameters) {
      return makeRawAesEax((AesEaxParameters) parameters);
    }
    if (parameters instanceof AesGcmSivParameters) {
      return makeRawAesGcmSiv((AesGcmSivParameters) parameters);
    }
    throw new IllegalArgumentException("Illegal parameters" + parameters);
  }

  private static LegacyKmsEnvelopeAeadParameters.DekParsingStrategy getRequiredParsingStrategy(
      AeadParameters parameters) {
    if (parameters instanceof AesGcmParameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM;
    }
    if (parameters instanceof ChaCha20Poly1305Parameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_CHACHA20POLY1305;
    }
    if (parameters instanceof XChaCha20Poly1305Parameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_XCHACHA20POLY1305;
    }
    if (parameters instanceof AesCtrHmacAeadParameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_CTR_HMAC;
    }
    if (parameters instanceof AesEaxParameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_EAX;
    }
    if (parameters instanceof AesGcmSivParameters) {
      return LegacyKmsEnvelopeAeadParameters.DekParsingStrategy.ASSUME_AES_GCM_SIV;
    }
    throw new IllegalArgumentException("Illegal parameters" + parameters);
  }

  /**
   * Returns a new {@link KeyTemplate} that can generate a {@link LegacyKmsEnvelopeAeadKey} whose
   * key encrypting key (KEK) is pointing to {@code kekUri} and DEK template is {@code dekTemplate}
   * (or a derived version of it).
   *
   * <p>It requires that a {@code KmsClient} that can handle {@code kekUri} is registered. Avoid
   * registering it more than once.
   *
   * <p><b>Note: </b> Unlike other templates, when you call {@link KeysetHandle#generateNew} with
   * this template Tink does not generate new key material, but instead creates a reference to the
   * remote KEK.
   *
   * <p>The second argument of the passed in template is ignoring the Variant, and assuming
   * NO_PREFIX instead.
   *
   * @deprecated Instead of registring a {@code KmsClient}, and creating an {@code Aead} using
   *     {@code KeysetHandle.generateNew(KmsEnvelopeAeadKeyManager.createKeyTemplate(keyUri,
   *     KeyTemplates.get("AES128_GCM"))).getPrimitive(Aead.class)}, create the {@code Aead}
   *     directly using {@code KmsEnvelopeAead.create(PredefinedAeadParameters.AES256_GCM,
   *     kmsClient.getAead(keyUri))}, without registering any {@code KmsClient}.
   */
  @AccessesPartialKey
  @Deprecated // We do not recommend using this API, but there are no plans to remove it.
  public static KeyTemplate createKeyTemplate(String kekUri, KeyTemplate dekTemplate) {
    try {
      Parameters parameters = dekTemplate.toParameters();
      AeadParameters outputPrefixRawParameters = makeRaw(parameters);
      LegacyKmsEnvelopeAeadParameters legacyKmsEnvelopeAeadParameters =
          LegacyKmsEnvelopeAeadParameters.builder()
              .setKekUri(kekUri)
              .setDekParsingStrategy(getRequiredParsingStrategy(outputPrefixRawParameters))
              .setDekParametersForNewKeys(outputPrefixRawParameters)
              .build();
      return KeyTemplate.createFrom(legacyKmsEnvelopeAeadParameters);
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException(
          "Cannot create LegacyKmsEnvelopeAeadParameters for template: " + dekTemplate, e);
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    LegacyKmsEnvelopeAeadProtoSerialization.register();
    MutableKeyCreationRegistry.globalInstance()
        .add(KEY_CREATOR, LegacyKmsEnvelopeAeadParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(LEGACY_KMS_ENVELOPE_AEAD_PRIMITIVE_CONSTRUCTOR);
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  private KmsEnvelopeAeadKeyManager() {}
}
