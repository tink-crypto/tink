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
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.internal.AesGcmProtoSerialization;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.TinkBugException;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.util.SecretBytes;
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
public final class AesGcmKeyManager {
  private static final void validate(AesGcmParameters parameters) throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() == 24) {
      throw new GeneralSecurityException("192 bit AES GCM Parameters are not valid");
    }
  }

  private static final PrimitiveConstructor<AesGcmKey, Aead> AES_GCM_PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(AesGcmJce::create, AesGcmKey.class, Aead.class);

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesGcmKey";
  }

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesGcmKey.parser());

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

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesGcmParameters>
      KEY_DERIVER = AesGcmKeyManager::createAesGcmKeyFromRandomness;

  @AccessesPartialKey
  static AesGcmKey createAesGcmKeyFromRandomness(
      AesGcmParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    validate(parameters);
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesGcmParameters> KEY_CREATOR =
      AesGcmKeyManager::createAesGcmKey;

  @AccessesPartialKey
  private static AesGcmKey createAesGcmKey(
      AesGcmParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validate(parameters);
    return AesGcmKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
    }
    AesGcmProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_GCM_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, AesGcmParameters.class);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesGcmParameters.class);
    try {
      KeyManagerRegistry.globalInstance()
          .registerKeyManagerWithFipsCompatibility(legacyKeyManager, FIPS, newKeyAllowed);
    } catch (GeneralSecurityException e) {
      throw new TinkBugException("AesGcmKeyManager registration failed unexpectedly", e);
    }
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

  private AesGcmKeyManager() {}
}
