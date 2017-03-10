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
package com.google.cloud.crypto.tink.hybrid;

import com.google.cloud.crypto.tink.CryptoFormat;
import com.google.cloud.crypto.tink.HybridDecrypt;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.subtle.HybridDecryptBase;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * HybridDecryptFactory allows obtaining a HybridDecrypt-primitive from a {@code KeysetHandle}.
 *
 * HybridDecryptFactory gets primitives from the {@code Registry}. The factory allows initalizing
 * the {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a HybridDecrypt primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   HybridDecryptFactory.registerStandardKeyTypes();
 *   HybridDecrypt hybridDecrypt = HybridDecryptFactory.getPrimitive(keysetHandle);
 *   byte[] ciphertext = ...;
 *   byte[] contextInfo = ...;
 *   byte[] plaintext = hybridEncypt.decrypt(ciphertext, contextInfo);
 *  }</pre>
 */
public final class HybridDecryptFactory {
  /**
   * Safe to use HybridDecrypt key types.
   */
  private static final Map<String, KeyManager<HybridDecrypt>> STANDARD_KEY_TYPES;
  /**
   * Deprecated HybridDecrypt key types, should not be used in new code.
   */
  private static final Map<String, KeyManager<HybridDecrypt>> LEGACY_KEY_TYPES;
  static {
    Map<String, KeyManager<HybridDecrypt>> standard =
        new HashMap<String, KeyManager<HybridDecrypt>>();
    standard.put(
        "type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPrivateKey",
        new EciesAeadHkdfPrivateKeyManager());
    STANDARD_KEY_TYPES = Collections.unmodifiableMap(standard);

    Map<String, KeyManager<HybridDecrypt>> legacy =
        new HashMap<String, KeyManager<HybridDecrypt>>();
    LEGACY_KEY_TYPES = Collections.unmodifiableMap(legacy);
  }
  /**
   * Registers standard HybridDecrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<HybridDecrypt>> entry : STANDARD_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }
  /**
   * Registers legacy HybridDecrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<HybridDecrypt>> entry : LEGACY_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }
  /**
   * @return a HybridDecrypt primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static HybridDecrypt getPrimitive(final KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, null /* keyManager */);
  }
  /**
   * @return a HybridDecrypt primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static HybridDecrypt getPrimitive(final KeysetHandle keysetHandle,
      final KeyManager<HybridDecrypt> keyManager)
      throws GeneralSecurityException {
    PrimitiveSet<HybridDecrypt> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
    return new HybridDecryptBase() {
      @Override
      public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
          throws GeneralSecurityException {
        if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
          byte[] prefix = Arrays.copyOfRange(ciphertext, 0, CryptoFormat.NON_RAW_PREFIX_SIZE);
          byte[] ciphertextNoPrefix = Arrays.copyOfRange(
              ciphertext,
              CryptoFormat.NON_RAW_PREFIX_SIZE,
              ciphertext.length);
          List<PrimitiveSet<HybridDecrypt>.Entry<HybridDecrypt>> entries =
              primitives.getPrimitive(prefix);
          for (PrimitiveSet<HybridDecrypt>.Entry<HybridDecrypt> entry : entries) {
            try {
              return entry.getPrimitive().decrypt(ciphertextNoPrefix, contextInfo);
            } catch (GeneralSecurityException e) {
              continue;
            }
          }
        }
        // Let's try all RAW keys.
        List<PrimitiveSet<HybridDecrypt>.Entry<HybridDecrypt>> entries =
            primitives.getRawPrimitives();
        for (PrimitiveSet<HybridDecrypt>.Entry<HybridDecrypt> entry : entries) {
          try {
            return entry.getPrimitive().decrypt(ciphertext, contextInfo);
          } catch (GeneralSecurityException e) {
            continue;
          }
        }
        // nothing works.
        throw new GeneralSecurityException("decryption failed");
      }
    };
  }
}
