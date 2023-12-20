// Copyright 2017 Google LLC
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
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfAesCmac;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesCmacKeyPrf} keys and produces new instances of {@code
 * AesCmacPrf}.
 */
public final class AesCmacPrfKeyManager {
  private static Prf createPrimitive(AesCmacPrfKey key) throws GeneralSecurityException {
    validate(key.getParameters());
    return PrfAesCmac.create(key);
  }

  private static final PrimitiveConstructor<com.google.crypto.tink.prf.AesCmacPrfKey, Prf>
      PRF_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesCmacPrfKeyManager::createPrimitive,
              com.google.crypto.tink.prf.AesCmacPrfKey.class,
              Prf.class);

  private static void validate(AesCmacPrfParameters parameters) throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() != 32) {
      throw new GeneralSecurityException("Key size must be 32 bytes");
    }
  }

  private static final KeyManager<Prf> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          getKeyType(),
          Prf.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesCmacPrfKey.parser());

  @AccessesPartialKey
  private static AesCmacPrfKey newKey(
      AesCmacPrfParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (idRequirement != null) {
      throw new GeneralSecurityException("Id Requirement is not supported for AES CMAC PRF keys");
    }
    validate(parameters);
    return AesCmacPrfKey.create(parameters, SecretBytes.randomBytes(parameters.getKeySizeBytes()));
  }

  @SuppressWarnings("InlineLambdaConstant") // We need a correct Object#equals in registration.
  private static final MutableKeyCreationRegistry.KeyCreator<AesCmacPrfParameters> KEY_CREATOR =
      AesCmacPrfKeyManager::newKey;

  static String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put("AES256_CMAC_PRF", PredefinedPrfParameters.AES_CMAC_PRF);
    // Identical to AES256_CMAC_PRF, needed for backward compatibility with PrfKeyTemplates.
    result.put("AES_CMAC_PRF", PredefinedPrfParameters.AES_CMAC_PRF);
    return Collections.unmodifiableMap(result);
  }

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    AesCmacPrfProtoSerialization.register();
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesCmacPrfParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(PRF_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  /**
   * Returns a {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   * parameters:
   *
   * <ul>
   *   <li>Key size: 32 bytes
   *   <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   * </ul>
   *
   *
   *
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW}
   *     </ul>
   */
  public static final KeyTemplate aes256CmacTemplate() {
    return exceptionIsBug(() -> KeyTemplate.createFrom(AesCmacPrfParameters.create(32)));
  }

  private AesCmacPrfKeyManager() {}
}
