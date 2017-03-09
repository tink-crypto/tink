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

package com.google.cloud.crypto.tink.signature;

import com.google.cloud.crypto.tink.KeyManager;
import com.google.cloud.crypto.tink.KeysetHandle;
import com.google.cloud.crypto.tink.PrimitiveSet;
import com.google.cloud.crypto.tink.PublicKeySign;
import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.subtle.Util;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * PublicKeySignFactory allows obtaining a {@code PublicKeySign} primitive from a
 * {@code KeysetHandle}.
 *
 * PublicKeySignFactory gets primitives from the {@code Registry}. The factory allows initalizing
 * the {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For example, here is how one can obtain and use a PublicKeySign primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   PublicKeySignFactory.registerStandardKeyTypes();
 *   PublicKeySign signer = PublicKeySignFactory.getPrimitive(keysetHandle);
 *   byte[] data = ...;
 *   byte[] signature = signer.sign(data);
 *  }</pre>
 */

public final class PublicKeySignFactory {
  /**
   * Safe to use PublicKeySign key types.
   */
  private static final Map<String, KeyManager<PublicKeySign>> STANDARD_KEY_TYPES;

  /**
   * Deprecated PublicKeySign key types, should not be used in new code.
   */
  private static final Map<String, KeyManager<PublicKeySign>> LEGACY_KEY_TYPES;

  static {
    Map<String, KeyManager<PublicKeySign>> standard =
        new HashMap<String, KeyManager<PublicKeySign>>();
    standard.put("type.googleapis.com/google.cloud.crypto.tink.EcdsaPrivateKey",
        new EcdsaSignKeyManager());
    STANDARD_KEY_TYPES = Collections.unmodifiableMap(standard);

    Map<String, KeyManager<PublicKeySign>> legacy =
        new HashMap<String, KeyManager<PublicKeySign>>();
    LEGACY_KEY_TYPES = Collections.unmodifiableMap(legacy);
  }
  /**
   * Registers standard PublicKeySign key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<PublicKeySign>> entry : STANDARD_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }

  /**
   * Registers legacy PublicKeySign key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    for (Entry<String, KeyManager<PublicKeySign>> entry : LEGACY_KEY_TYPES.entrySet()) {
      Registry.INSTANCE.registerKeyManager(entry.getKey(), entry.getValue());
    }
  }

  /**
   * @return a PublicKeySign primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static PublicKeySign getPrimitive(final KeysetHandle keysetHandle)
      throws GeneralSecurityException {
        return getPrimitive(keysetHandle, null /* keyManager */);
      }

  /**
   * @return a PublicKeySign primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static PublicKeySign getPrimitive(final KeysetHandle keysetHandle,
      final KeyManager<PublicKeySign> keyManager)
      throws GeneralSecurityException {
        PrimitiveSet<PublicKeySign> primitives =
            Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
        return new PublicKeySign() {
          @Override
          public byte[] sign(final byte[] data) throws GeneralSecurityException {
            return Util.concat(
                primitives.getPrimary().getIdentifier(),
                primitives.getPrimary().getPrimitive().sign(data));
          }
        };
      }
}
