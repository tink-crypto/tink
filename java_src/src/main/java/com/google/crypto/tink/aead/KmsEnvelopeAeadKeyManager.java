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
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.KeyTemplateProtoConverter;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKey;
import com.google.crypto.tink.proto.KmsEnvelopeAeadKeyFormat;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;

/**
 * This key manager generates new {@code KmsEnvelopeAeadKey} keys and produces new instances of
 * {@code KmsEnvelopeAead}.
 */
public class KmsEnvelopeAeadKeyManager extends KeyTypeManager<KmsEnvelopeAeadKey> {
  private static final String TYPE_URL =
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

  KmsEnvelopeAeadKeyManager() {
    super(
        KmsEnvelopeAeadKey.class,
        new PrimitiveFactory<Aead, KmsEnvelopeAeadKey>(Aead.class) {
          @Override
          public Aead getPrimitive(KmsEnvelopeAeadKey keyProto) throws GeneralSecurityException {
            String keyUri = keyProto.getParams().getKekUri();
            KmsClient kmsClient = KmsClients.get(keyUri);
            Aead remote = kmsClient.getAead(keyUri);
            return new KmsEnvelopeAead(keyProto.getParams().getDekTemplate(), remote);
          }
        });
  }

  @Override
  public String getKeyType() {
    return TYPE_URL;
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.REMOTE;
  }

  @Override
  public void validateKey(KmsEnvelopeAeadKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    if (!KmsEnvelopeAead.isSupportedDekKeyType(key.getParams().getDekTemplate().getTypeUrl())) {
      throw new GeneralSecurityException(
          "Unsupported DEK key type: "
              + key.getParams().getDekTemplate().getTypeUrl()
              + ". Only Tink AEAD key types are supported.");
    }
  }

  @Override
  public KmsEnvelopeAeadKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return KmsEnvelopeAeadKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<KmsEnvelopeAeadKeyFormat, KmsEnvelopeAeadKey> keyFactory() {
    return new KeyFactory<KmsEnvelopeAeadKeyFormat, KmsEnvelopeAeadKey>(
        KmsEnvelopeAeadKeyFormat.class) {
      @Override
      public void validateKeyFormat(KmsEnvelopeAeadKeyFormat format)
          throws GeneralSecurityException {
        if (!KmsEnvelopeAead.isSupportedDekKeyType(format.getDekTemplate().getTypeUrl())) {
          throw new GeneralSecurityException(
              "Unsupported DEK key type: "
                  + format.getDekTemplate().getTypeUrl()
                  + ". Only Tink AEAD key types are supported.");
        }
        if (format.getKekUri().isEmpty() || !format.hasDekTemplate()) {
          throw new GeneralSecurityException("invalid key format: missing KEK URI or DEK template");
        }
      }

      @Override
      public KmsEnvelopeAeadKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return KmsEnvelopeAeadKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public KmsEnvelopeAeadKey createKey(KmsEnvelopeAeadKeyFormat format) {
        return KmsEnvelopeAeadKey.newBuilder().setParams(format).setVersion(getVersion()).build();
      }
    };
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
   * <p><b>Note: </b> Unlike other templates, when you call {@link KeysetHandle#generateNew} with
   * this template Tink does not generate new key material, but instead creates a reference to the
   * remote KEK.
   *
   * <p>The second argument of the passed in template is used ignoring the Variant, and assuming
   * NO_PREFIX instead.
   */
  @AccessesPartialKey
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
    Registry.registerKeyManager(new KmsEnvelopeAeadKeyManager(), newKeyAllowed);
    LegacyKmsEnvelopeAeadProtoSerialization.register();
  }

  static KmsEnvelopeAeadKeyFormat createKeyFormat(String kekUri, KeyTemplate dekTemplate)
      throws GeneralSecurityException, InvalidProtocolBufferException {
    com.google.crypto.tink.proto.KeyTemplate protoDekTemplate =
        KeyTemplateProtoConverter.toProto(dekTemplate);
    if (!KmsEnvelopeAead.isSupportedDekKeyType(protoDekTemplate.getTypeUrl())) {
      throw new IllegalArgumentException(
          "Unsupported DEK key type: "
              + protoDekTemplate.getTypeUrl()
              + ". Only Tink AEAD key types are supported.");
    }
    return KmsEnvelopeAeadKeyFormat.newBuilder()
        .setDekTemplate(protoDekTemplate)
        .setKekUri(kekUri)
        .build();
  }
}
