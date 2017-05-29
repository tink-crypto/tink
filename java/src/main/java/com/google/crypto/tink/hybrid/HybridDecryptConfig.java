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
package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import java.security.GeneralSecurityException;

/**
 * HybridDecryptConfig offers convenience methods for initializing {@code HybridDecryptFactory}
 * and the underlying {@code Registry.INSTANCE}.  In particular, it  allows for initalizing the
 * {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For more information on how to obtain and use HybridDecrypt primitives,
 * see {@code HybridDecryptFactory}.
 */
public final class HybridDecryptConfig {
  /**
   * Registers standard HybridDecrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();
    registerKeyManager(new EciesAeadHkdfPrivateKeyManager());
  }
  /**
   * Registers legacy HybridDecrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    ;
  }

  /**
   * Registers the given {@code keyManager} for the key type {@code keyManager.getKeyType()}.
   * @return true if registration of {@code keyManager} was successful, false if
   *         there already exisits a key manager for {@code keyManager.getKeyType()}.
   * @throws GeneralSecurityException
   */
  public static boolean registerKeyManager(final KeyManager<HybridDecrypt> keyManager)
      throws GeneralSecurityException {
    return Registry.INSTANCE.registerKeyManager(keyManager.getKeyType(), keyManager);
  }
}
