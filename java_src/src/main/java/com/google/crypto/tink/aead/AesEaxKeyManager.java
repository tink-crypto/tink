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

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.PrimitiveFactory;
import com.google.crypto.tink.proto.AesEaxKey;
import com.google.crypto.tink.proto.AesEaxKeyFormat;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This key manager generates new {@code AesEaxKey} keys and produces new instances of {@code
 * AesEaxJce}.
 */
public final class AesEaxKeyManager extends KeyTypeManager<AesEaxKey> {
  private static final PrimitiveConstructor<com.google.crypto.tink.aead.AesEaxKey, Aead>
      AES_EAX_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesEaxJce::create, com.google.crypto.tink.aead.AesEaxKey.class, Aead.class);

  AesEaxKeyManager() {
    super(
        AesEaxKey.class,
        new PrimitiveFactory<Aead, AesEaxKey>(Aead.class) {
          @Override
          public Aead getPrimitive(AesEaxKey key) throws GeneralSecurityException {
            return new AesEaxJce(key.getKeyValue().toByteArray(), key.getParams().getIvSize());
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesEaxKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public TinkFipsUtil.AlgorithmFipsCompatibility fipsStatus() {
    return TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.SYMMETRIC;
  }

  @Override
  public void validateKey(AesEaxKey key) throws GeneralSecurityException {
    Validators.validateVersion(key.getVersion(), getVersion());
    Validators.validateAesKeySize(key.getKeyValue().size());
    if (key.getParams().getIvSize() != 12 && key.getParams().getIvSize() != 16) {
      throw new GeneralSecurityException("invalid IV size; acceptable values have 12 or 16 bytes");
    }
  }

  @Override
  public AesEaxKey parseKey(ByteString byteString) throws InvalidProtocolBufferException {
    return AesEaxKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public KeyFactory<AesEaxKeyFormat, AesEaxKey> keyFactory() {
    return new KeyFactory<AesEaxKeyFormat, AesEaxKey>(AesEaxKeyFormat.class) {
      @Override
      public void validateKeyFormat(AesEaxKeyFormat format) throws GeneralSecurityException {
        Validators.validateAesKeySize(format.getKeySize());
        if (format.getParams().getIvSize() != 12 && format.getParams().getIvSize() != 16) {
          throw new GeneralSecurityException(
              "invalid IV size; acceptable values have 12 or 16 bytes");
        }
      }

      @Override
      public AesEaxKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return AesEaxKeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public AesEaxKey createKey(AesEaxKeyFormat format) throws GeneralSecurityException {
        return AesEaxKey.newBuilder()
            .setKeyValue(ByteString.copyFrom(Random.randBytes(format.getKeySize())))
            .setParams(format.getParams())
            .setVersion(getVersion())
            .build();
      }
    };
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("AES128_EAX", PredefinedAeadParameters.AES128_EAX);
        result.put(
            "AES128_EAX_RAW",
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setKeySizeBytes(16)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                .build());
        result.put("AES256_EAX", PredefinedAeadParameters.AES256_EAX);
        result.put(
            "AES256_EAX_RAW",
            AesEaxParameters.builder()
                .setIvSizeBytes(16)
                .setKeySizeBytes(32)
                .setTagSizeBytes(16)
                .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                .build());

        return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerKeyManager(new AesEaxKeyManager(), newKeyAllowed);
    AesEaxProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_EAX_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate aes128EaxTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 16 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate rawAes128EaxTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(16)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate aes256EaxTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of AES-EAX with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>IV size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate rawAes256EaxTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesEaxParameters.builder()
                    .setIvSizeBytes(16)
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesEaxParameters.Variant.NO_PREFIX)
                    .build()));
  }

}
