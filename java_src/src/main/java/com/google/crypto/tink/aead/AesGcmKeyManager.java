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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.AesGcmKey;
import com.google.crypto.tink.proto.AesGcmKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesGcmKey} keys and produces new instances of {@code
 * AesGcmJce}.
 */
public final class AesGcmKeyManager extends KeyTypeManager<AesGcmKey> {
  AesGcmKeyManager() {
    super(
        AesGcmKey.class,
        new PrimitiveFactory<Aead, AesGcmKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesGcmKey key) throws GeneralSecurityException {
            return new AesGcmJce(key.getKeyValue().toByteArray());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesGcmKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    Validators.validateAesKeySize(key.getKeyValue().size());
  }

  @Override
  public AesGcmKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesGcmKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesGcmKeyFormat, AesGcmKey> keyFactory() {
    return new KeyFactory<AesGcmKeyFormat, AesGcmKey>(AesGcmKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesGcmKeyFormat format) throws GeneralSecurityException {
        Validators.validateAesKeySize(format.getKeySize());
      }

      @Override
      public AesGcmKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesGcmKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesGcmKey createKey(AesGcmKeyFormat format) throws GeneralSecurityException {
        return AesGcmKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setVersion(getVersion())
            .build();
      }

      @Override
      public com.google.crypto.tink.aead.AesGcmKey createKeyFromRandomness(
          Parameters parameters,
          InputStream stream,
          @Nullable Integer idRequirement,
          SecretKeyAccess access)
          throws GeneralSecurityException {
        if (parameters instanceof AesGcmParameters) {
          return createAesGcmKeyFromRandomness(
              (AesGcmParameters) parameters, stream, idRequirement, access);
        }
        throw new GeneralSecurityException(
            "Unexpected parameters: expected AesGcmParameters, but got: " + parameters);
      }
    };
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("AES128_GCM", PredefinedAeadParameters.AES128_GCM);
        result.put(
            "AES128_GCM_RAW",
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setKeySizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
        result.put("AES256_GCM", PredefinedAeadParameters.AES256_GCM);
        result.put(
            "AES256_GCM_RAW",
            AesGcmParameters.builder()
                .setIvSizeBytes(12)
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                .build());
    return Collections.unmodifiableMap(result);
  }

  @AccessesPartialKey
  static com.google.crypto.tink.aead.AesGcmKey createAesGcmKeyFromRandomness(
      AesGcmParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesGcmKeyManager(), newKeyAllowed);
    AesGcmProtoSerialization.register();
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate aes128GcmTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *     <p>Keys generated from this template should create ciphertexts compatible with other
   *     libraries.
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate rawAes128GcmTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate aes256GcmTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-GCM with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   *     <p>Keys generated from this template should create ciphertexts compatible with other
   *     libraries.
   *     <p>On Android KitKat (API level 19), the {@link com.google.crypto.tink.Aead} instance
   *     generated by this key template does not support associated data. It might not work at all
   *     in older versions.
   */
  public static final KeyTemplate rawAes256GcmTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmParameters.builder()
                    .setIvSizeBytes(12)
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesGcmParameters.Variant.NO_PREFIX)
                    .build()));
  }

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
  };
}
