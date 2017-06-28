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

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.subtle.SubtleUtil;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

/**
 * HybridEncryptFactory allows obtaining a HybridEncrypt primitive from a {@code KeysetHandle}.
 *
 * HybridEncryptFactory gets primitives from the {@code Registry.INSTANCE}, which can be initialized
 * via convenience methods from {@code HybridEncryptConfig}. Here is an example how one can obtain
 * and use a HybridEncrypt primitive:
 * <pre>   {@code
 *   KeysetHandle keysetHandle = ...;
 *   HybridEncryptConfig.registerStandardKeyTypes();
 *   HybridEncrypt hybridEncrypt = HybridEncryptFactory.getPrimitive(keysetHandle);
 *   byte[] plaintext = ...;
 *   byte[] contextInfo = ...;
 *   byte[] ciphertext = hybridEncypt.encrypt(plaintext, contextInfo);
 *  }</pre>
 * The returned primitive works with a keyset (rather than a single key). To encrypt a message,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix
 * associated with the primary key.
 */
public final class HybridEncryptFactory {
  private static final Logger logger = Logger.getLogger(HybridEncryptFactory.class.getName());

  static {
    try {
      AeadConfig.registerStandardKeyTypes();
      MacConfig.registerStandardKeyTypes();
    } catch (GeneralSecurityException e) {
      logger.severe("cannot register key managers: " + e);
    }
  }
  /**
   * Registers standard HybridEncrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    Registry.INSTANCE.registerKeyManager(
        EciesAeadHkdfPublicKeyManager.TYPE_URL,
        new EciesAeadHkdfPublicKeyManager());
  }
  /**
   * Registers legacy HybridEncrypt key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerLegacyKeyTypes() throws GeneralSecurityException {
    ;
  }
  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(KeysetHandle keysetHandle)
      throws GeneralSecurityException {
    return getPrimitive(keysetHandle, /* keyManager= */null);
  }
  /**
   * @return a HybridEncrypt primitive from a {@code keysetHandle} and a custom {@code keyManager}.
   * @throws GeneralSecurityException
   */
  public static HybridEncrypt getPrimitive(
      KeysetHandle keysetHandle, final KeyManager<HybridEncrypt> keyManager)
      throws GeneralSecurityException {
    final PrimitiveSet<HybridEncrypt> primitives =
        Registry.INSTANCE.getPrimitives(keysetHandle, keyManager);
    return new HybridEncrypt() {
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
