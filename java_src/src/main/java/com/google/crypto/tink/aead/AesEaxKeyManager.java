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
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesEaxJce;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesEaxKey} keys and produces new instances of {@code
 * AesEaxJce}.
 */
public final class AesEaxKeyManager {
  private static final void validate(AesEaxParameters parameters) throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() == 24) {
      throw new GeneralSecurityException("192 bit AES GCM Parameters are not valid");
    }
  }

  private static final PrimitiveConstructor<AesEaxKey, Aead> AES_EAX_PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(AesEaxJce::create, AesEaxKey.class, Aead.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesEaxKey";
  }

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesEaxKey.parser());

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

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesEaxParameters> KEY_CREATOR =
      AesEaxKeyManager::createAesEaxKey;

  @AccessesPartialKey
  private static com.google.crypto.tink.aead.AesEaxKey createAesEaxKey(
      AesEaxParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validate(parameters);
    return com.google.crypto.tink.aead.AesEaxKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    AesEaxProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_EAX_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesEaxParameters.class);
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
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

  private AesEaxKeyManager() {}
}
