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

package com.google.crypto.tink.daead;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.daead.internal.AesSivProtoSerialization;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.AesSiv;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesSivKey} keys and produces new instances of {@code
 * AesSiv}.
 */
public final class AesSivKeyManager {
  private static DeterministicAead createDeterministicAead(AesSivKey key)
      throws GeneralSecurityException {
    validateParameters(key.getParameters());
    return AesSiv.create(key);
  }

  private static final PrimitiveConstructor<AesSivKey, DeterministicAead>
      AES_SIV_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesSivKeyManager::createDeterministicAead, AesSivKey.class, DeterministicAead.class);

  private static final int KEY_SIZE_IN_BYTES = 64;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesSivKey";
  }

  private static final KeyManager<DeterministicAead> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          DeterministicAead.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesSivKey.parser());

  private static void validateParameters(AesSivParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() != KEY_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException(
          "invalid key size: "
              + parameters.getKeySizeBytes()
              + ". Valid keys must have "
              + KEY_SIZE_IN_BYTES
              + " bytes.");
    }
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<AesSivParameters>
      KEY_DERIVER = AesSivKeyManager::createAesSivKeyFromRandomness;

  @AccessesPartialKey
  static AesSivKey createAesSivKeyFromRandomness(
      AesSivParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    validateParameters(parameters);
    return AesSivKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesSivParameters> KEY_CREATOR =
      AesSivKeyManager::newKey;

  @AccessesPartialKey
  static AesSivKey newKey(AesSivParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validateParameters(parameters);
    return AesSivKey.builder()
        .setParameters(parameters)
        .setIdRequirement(idRequirement)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put("AES256_SIV", PredefinedDeterministicAeadParameters.AES256_SIV);
    result.put(
        "AES256_SIV_RAW",
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build());
    return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering AES SIV is not supported in FIPS mode");
    }
    AesSivProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(AES_SIV_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, AesSivParameters.class);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesSivParameters.class);
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * @return a {@code KeyTemplate} that generates new instances of AES-SIV-CMAC keys.
   */
  public static final KeyTemplate aes256SivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesSivParameters.builder()
                    .setKeySizeBytes(KEY_SIZE_IN_BYTES)
                    .setVariant(AesSivParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@code KeyTemplate} that generates new instances of AES-SIV-CMAC keys. Keys generated
   *     from this template create ciphertexts compatible with other libraries.
   */
  public static final KeyTemplate rawAes256SivTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesSivParameters.builder()
                    .setKeySizeBytes(KEY_SIZE_IN_BYTES)
                    .setVariant(AesSivParameters.Variant.NO_PREFIX)
                    .build()));
  }

  private AesSivKeyManager() {}
}
