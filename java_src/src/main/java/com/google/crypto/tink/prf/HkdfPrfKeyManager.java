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
package com.google.crypto.tink.prf;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code HkdfPrfKey} keys and produces new instances of {@code
 * HkdfStreamingPrf} and {@code HkdfPrf}.
 */
public class HkdfPrfKeyManager {
  private static void validate(HkdfPrfParameters parameters) throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() < MIN_KEY_SIZE) {
      throw new GeneralSecurityException("Key size must be at least " + MIN_KEY_SIZE);
    }
    if (parameters.getHashType() != HkdfPrfParameters.HashType.SHA256
        && parameters.getHashType() != HkdfPrfParameters.HashType.SHA512) {
      throw new GeneralSecurityException("Hash type must be SHA256 or SHA512");
    }
  }

  private static StreamingPrf createStreamingPrf(HkdfPrfKey key) throws GeneralSecurityException {
    validate(key.getParameters());
    return HkdfStreamingPrf.create(key);
  }

  private static Prf createPrf(HkdfPrfKey key) throws GeneralSecurityException {
    return PrfImpl.wrap(createStreamingPrf(key));
  }

  private static final PrimitiveConstructor<HkdfPrfKey, StreamingPrf>
      STREAMING_HKDF_PRF_CONSTRUCTOR =
          PrimitiveConstructor.create(
              HkdfPrfKeyManager::createStreamingPrf, HkdfPrfKey.class, StreamingPrf.class);
  private static final PrimitiveConstructor<HkdfPrfKey, Prf> HKDF_PRF_CONSTRUCTOR =
      PrimitiveConstructor.create(HkdfPrfKeyManager::createPrf, HkdfPrfKey.class, Prf.class);

  private static final KeyManager<Prf> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Prf.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.HkdfPrfKey.parser());

  @AccessesPartialKey
  private static HkdfPrfKey newKey(HkdfPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("Id Requirement is not supported for HKDF PRF keys");
    }
    validate(parameters);
    return HkdfPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  static final MutableKeyCreationRegistry.KeyCreator<HkdfPrfParameters> KEY_CREATOR =
      HkdfPrfKeyManager::newKey;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HkdfPrfKey";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put("HKDF_SHA256", PredefinedPrfParameters.HKDF_SHA256);
    return Collections.unmodifiableMap(result);
  }

  // We use a somewhat larger minimum key size than usual, because PRFs might be used by many users,
  // in which case the security can degrade by a factor depending on the number of users. (Discussed
  // for example in https://eprint.iacr.org/2012/159)
  private static final int MIN_KEY_SIZE = 32;

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_NOT_FIPS.isCompatible()) {
      throw new GeneralSecurityException("Registering HKDF PRF is not supported in FIPS mode");
    }
    HkdfPrfProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance().registerPrimitiveConstructor(HKDF_PRF_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(STREAMING_HKDF_PRF_CONSTRUCTOR);
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, HkdfPrfParameters.class);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    KeyManagerRegistry.globalInstance().registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  public static String staticKeyType() {
    return HkdfPrfKeyManager.getKeyType();
  }

  /**
   * Generates a {@link KeyTemplate} for HKDF-PRF keys with the following parameters.
   *
   * <ul>
   *   <li>Hash function: SHA256
   *   <li>HMAC key size: 32 bytes
   *   <li>Salt: empty
   * </ul>
   */
  public static final KeyTemplate hkdfSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HkdfPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HkdfPrfParameters.HashType.SHA256)
                    .build()));
  }

  private HkdfPrfKeyManager() {}
}
