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

import com.google.cloud.crypto.tink.HybridEncrypt;
import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.aead.AeadFactory;
import com.google.cloud.crypto.tink.mac.MacFactory;
import com.google.cloud.crypto.tink.subtle.HybridEncryptBase;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

/**
 * HybridEncryptFactory allows obtaining a HybridEncrypt-primitive from a {@code KeysetHandle}.
 *
 * HybridEncryptFactory gets primitives from the {@code Registry}. The factory allows initalizing
 * the {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a HybridEncrypt primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   HybridEncryptFactory.registerStandardKeyTypes();
 *   HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(keysetHandle);
 *   byte[] plaintext = ...;
 *   byte[] contextInfo = ...;
 *   byte[] ciphertext = hybridEncypt.encrypt(plaintext, contextInfo);
 *  }</pre>
 */
public final class HybridEncryptFactory {
  private static final Logger logger =
      Logger.getLogger(HybridEncryptFactory.class.getName());
  /**
   * Safe to use HybridEncrypt key types.
   */
  private static final Map<String, KeyManager<HybridEncrypt>> STANDARD_KEY_TYPES;
  /**
   * Deprecated HybridEncrypt key types, should not be used in new code.
   */
  private static final Map<String, KeyManager<HybridEncrypt>> LEGACY_KEY_TYPES;
  static {
    Map<String, KeyManager<HybridEncrypt>> standard =
        new HashMap<String, KeyManager<HybridEncrypt>>();
    standard.put(
        "type.googleapis.com/google.cloud.crypto.tink.EciesAeadHkdfPublicKey",
        new EciesAeadHkdfPublicKeyManager());
    STANDARD_KEY_TYPES = Collections.unmodifiableMap(standard);

    Map<String, KeyManager<HybridEncrypt>> legacy =
        new HashMap<String, KeyManager<HybridEncrypt>>();
    LEGACY_KEY_TYPES = Collections.unmodifiableMap(legacy);

    try {
      AeadFactory.registerStandardKeyTypes();
      MacFactory.registerStandardKeyTypes();
    } catch (GeneralSecurityException e) {
      logger.severe("Cannot register key managers: " + e);
    }
  }
  /**
   * Registers standard HybridEncrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<HybridEncrypt>> entry : STANDARD_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }
  /**
   * Registers legacy HybridEncrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<HybridEncrypt>> entry : LEGACY_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }
  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(final KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, null /* keyManager */);
  }
  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(final KeysetHandle keysetHandle,
      final KeyManager<HybridEncrypt> keyManager)
      throws GeneralSecurityException {
    PrimitiveSet<HybridEncrypt> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
    return new HybridEncryptBase() {
      @Override
      public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
          throws GeneralSecurityException {
        return SubtleUtil.concat(
            primitives.getPrimary().getIdentifier(),
            primitives.getPrimary().getPrimitive().encrypt(plaintext, contextInfo));
      }
    };
  }
}
