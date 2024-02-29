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

package com.google.crypto.tink.prf;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableKeyDerivationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.Util;
import com.google.crypto.tink.prf.internal.HmacPrfProtoSerialization;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfHmacJce;
import com.google.crypto.tink.util.SecretBytes;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code HmacPrfKey} keys and produces new instances of {@code
 * PrfHmacJce}.
 */
public final class HmacPrfKeyManager {

  private static final PrimitiveConstructor<com.google.crypto.tink.prf.HmacPrfKey, Prf>
      PRF_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              PrfHmacJce::create, com.google.crypto.tink.prf.HmacPrfKey.class, Prf.class);

  private static final KeyManager<Prf> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Prf.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.HmacPrfKey.parser());

  @AccessesPartialKey
  private static HmacPrfKey newKey(HmacPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("Id Requirement is not supported for HMAC PRF keys");
    }
    return HmacPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .build();
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<HmacPrfParameters> KEY_CREATOR =
      HmacPrfKeyManager::newKey;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.HmacPrfKey";
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyDerivationRegistry.InsecureKeyCreator<HmacPrfParameters>
      KEY_DERIVER = HmacPrfKeyManager::createHmacKeyFromRandomness;

  @AccessesPartialKey
  static com.google.crypto.tink.prf.HmacPrfKey createHmacKeyFromRandomness(
      HmacPrfParameters parameters,
      InputStream stream,
      @Nullable Integer idRequirement,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    return com.google.crypto.tink.prf.HmacPrfKey.builder()
        .setParameters(parameters)
        .setKeyBytes(Util.readIntoSecretBytes(stream, parameters.getKeySizeBytes(), access))
        .build();
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
        Map<String, Parameters> result = new HashMap<>();
        result.put("HMAC_SHA256_PRF", PredefinedPrfParameters.HMAC_SHA256_PRF);
        result.put("HMAC_SHA512_PRF", PredefinedPrfParameters.HMAC_SHA512_PRF);
    return Collections.unmodifiableMap(result);
  }

  private static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
    }
    HmacPrfProtoSerialization.register();
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PRF_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, HmacPrfParameters.class);
    MutableKeyDerivationRegistry.globalInstance().add(KEY_DERIVER, HmacPrfParameters.class);
    KeyManagerRegistry.globalInstance()
        .registerKeyManagerWithFipsCompatibility(legacyKeyManager, FIPS, newKeyAllowed);
  }

  /**
   * Returns a {@link KeyTemplate} that generates new instances of HMAC keys with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Hash function: SHA256
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   * </ul>
   */
  public static final KeyTemplate hmacSha256Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(32)
                    .setHashType(HmacPrfParameters.HashType.SHA256)
                    .build()));
  }

  /**
   * Returns a {@link KeyTemplate} that generates new instances of HMAC keys with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 64 bytes
   *   <li>Hash function: SHA512
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   * </ul>
   */
  public static final KeyTemplate hmacSha512Template() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                HmacPrfParameters.builder()
                    .setKeySizeBytes(64)
                    .setHashType(HmacPrfParameters.HashType.SHA512)
                    .build()));
  }

  private HmacPrfKeyManager() {}
}
