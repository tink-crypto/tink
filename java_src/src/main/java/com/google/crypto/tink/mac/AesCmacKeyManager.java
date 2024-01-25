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

package com.google.crypto.tink.mac;

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.LegacyKeyManagerImpl;
import com.google.crypto.tink.internal.MutableKeyCreationRegistry;
import com.google.crypto.tink.internal.MutableParametersRegistry;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.mac.internal.ChunkedAesCmacImpl;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.PrfMac;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This key manager generates new {@code AesCmacKey} keys and produces new instances of {@code
 * AesCmac}.
 */
public final class AesCmacKeyManager {
  private static final int KEY_SIZE_IN_BYTES = 32;

  // AesCmacParameters can be instantiated with 16 byte keys, but we only allow 32 byte keys
  // with non-subtle API.
  private static void validateParameters(AesCmacParameters parameters)
      throws GeneralSecurityException {
    if (parameters.getKeySizeBytes() != KEY_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("AesCmacKey size wrong, must be 32 bytes");
    }
  }

  @AccessesPartialKey
  private static AesCmacKey createAesCmacKey(
      AesCmacParameters parameters, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validateParameters(parameters);
    return AesCmacKey.builder()
        .setParameters(parameters)
        .setAesKeyBytes(SecretBytes.randomBytes(parameters.getKeySizeBytes()))
        .setIdRequirement(idRequirement)
        .build();
  }

  private static ChunkedMac createChunkedMac(AesCmacKey key) throws GeneralSecurityException {
    validateParameters(key.getParameters());
    return new ChunkedAesCmacImpl(key);
  }

  private static Mac createMac(AesCmacKey key) throws GeneralSecurityException {
    validateParameters(key.getParameters());
    return PrfMac.create(key);
  }

  private static final MutableKeyCreationRegistry.KeyCreator<AesCmacParameters> KEY_CREATOR =
      AesCmacKeyManager::createAesCmacKey;
  private static final PrimitiveConstructor<AesCmacKey, ChunkedMac>
      CHUNKED_MAC_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              AesCmacKeyManager::createChunkedMac, AesCmacKey.class, ChunkedMac.class);
  private static final PrimitiveConstructor<AesCmacKey, Mac> MAC_PRIMITIVE_CONSTRUCTOR =
      PrimitiveConstructor.create(AesCmacKeyManager::createMac, AesCmacKey.class, Mac.class);
  private static final KeyManager<Mac> legacyKeyManager =
      LegacyKeyManagerImpl.create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          Mac.class,
          KeyMaterialType.SYMMETRIC,
          com.google.crypto.tink.proto.AesCmacKey.parser());

  public static void register(boolean newKeyAllowed) throws GeneralSecurityException {
    AesCmacProtoSerialization.register();
    MutableKeyCreationRegistry.globalInstance().add(KEY_CREATOR, AesCmacParameters.class);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(CHUNKED_MAC_PRIMITIVE_CONSTRUCTOR);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(MAC_PRIMITIVE_CONSTRUCTOR);
    MutableParametersRegistry.globalInstance().putAll(namedParameters());
    Registry.registerKeyManager(legacyKeyManager, newKeyAllowed);
  }

  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> result = new HashMap<>();
    result.put("AES_CMAC", PredefinedMacParameters.AES_CMAC);
    result.put("AES256_CMAC", PredefinedMacParameters.AES_CMAC);
    result.put(
        "AES256_CMAC_RAW",
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesCmacParameters.Variant.NO_PREFIX)
            .build());
    return Collections.unmodifiableMap(result);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}
   *     </ul>
   */
  public static final KeyTemplate aes256CmacTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesCmacParameters.Variant.TINK)
                    .build()));
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of AES-CMAC keys with the following
   *     parameters:
   *     <ul>
   *       <li>Key size: 32 bytes
   *       <li>Tag size: 16 bytes
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix)
   *     </ul>
   */
  public static final KeyTemplate rawAes256CmacTemplate() {
    return exceptionIsBug(
        () ->
            KeyTemplate.createFrom(
                AesCmacParameters.builder()
                    .setKeySizeBytes(32)
                    .setTagSizeBytes(16)
                    .setVariant(AesCmacParameters.Variant.NO_PREFIX)
                    .build()));
  }

  private AesCmacKeyManager() {}
}
