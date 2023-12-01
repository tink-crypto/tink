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
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.aead.subtle.AesGcmSiv;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * This key manager generates new {@code AesGcmSivKey} keys and produces new instances of {@code
 * AesGcmSiv}.
 */
public final class AesGcmSivKeyManager {
  private static final PrimitiveConstructor<com.google.crypto.tink.aead.AesGcmSivKey, Aead>
      AES_GCM_SIV_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesGcmSiv::create, com.google.crypto.tink.aead.AesGcmSivKey.class, Aead.class);

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesGcmSivParameters> KEY_CREATOR =
      AesGcmSivKeyManager::createAesGcmSivKey;

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesGcmSivParameters>
      KEY_DERIVER = AesGcmSivKeyManager::createAesGcmSivKeyFromRandomness;

  private static final KeyManager<Aead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          Aead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesGcmSivKey.parser());

  @AccessesPartialKey
  static com.google.crypto.tink.aead.AesGcmSivKey createAesGcmSivKeyFromRandomness(
      AesGcmSivParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.AesGcmSivKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  @AccessesPartialKey
  private static com.google.crypto.tink.aead.AesGcmSivKey createAesGcmSivKey(
      AesGcmSivParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    return com.google.crypto.tink.aead.AesGcmSivKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();

    result.put(
        "AES128_GCM_SIV",
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build());
    result.put(
        "AES128_GCM_SIV_RAW",
        AesGcmSivParameters.builder()
            .setKeySizeBytes(16)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build());
    result.put(
        "AES256_GCM_SIV",
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.TINK)
            .build());
    result.put(
        "AES256_GCM_SIV_RAW",
        AesGcmSivParameters.builder()
            .setKeySizeBytes(32)
            .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
            .build());

    return Collections.unmodifiableMap(result);
  }

  private static boolean canUseAesGcmSive() {
    try {
      Cipher.getInstance("AES/GCM-SIV/NoPadding");
      return true;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
      return false;
    }
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (canUseAesGcmSive()) {
      AesGcmSivProtoSerialization.register();
      MutablePrimitiveRegistry.globalInstance()
          .registerPrimitiveConstructor(AES_GCM_SIV_PRIMITIVE_CONSTRUCTOR);
      MutableParametersRegistry.globalInstance().putAll(namedParameters());
      MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, AesGcmSivParameters.class);
      MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesGcmSivParameters.class);
      Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
    }
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   * </ul>
   */
  public static final KeyTemplate aes128GcmSivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build()));
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 16 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   * </ul>
   *
   * <p>Keys generated from this template should create ciphertexts compatible with other libraries.
   */
  public static final KeyTemplate rawAes128GcmSivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(16)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build()));
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   * </ul>
   */
  public static final KeyTemplate aes256GcmSivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesGcmSivParameters.Variant.TINK)
                    .build()));
  }

  /**
   * Creates and returns a {@link KeyTemplate} that generates new instances of AES-GCM-SIV with the
   * following parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   * </ul>
   *
   * <p>Keys generated from this template should create ciphertexts compatible with other libraries.
   */
  public static final KeyTemplate rawAes256GcmSivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesGcmSivParameters.builder()
                    .setKeySizeBytes(32)
                    .setVariant(AesGcmSivParameters.Variant.NO_PREFIX)
                    .build()));
  }

  private AesGcmSivKeyManager() {}
}
