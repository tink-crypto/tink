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
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;

/**
 * HybridEncryptConfig offers convenience methods for initializing
 * {@code HybridEncryptFactory} and the underlying {@code Registry}.
 *
 * For more information on how to obtain and use HybridEncrypt primitives,
 * see {@code HybridEncryptFactory}.
 */
public final class HybridEncryptConfig {
  /**
   * Registers standard (for the current release) HybridEncrypt key types
   * and their managers with the {@code Registry}.
   *
   * Deprecated-yet-still-supported key types are registered in
   * so-called "no new key"-mode, which allows for usage of existing
   * keys forbids generation of new key material.
   *
   * NOTE: as some HybridEncrypt key types use Aead-primitives, this method registers
   *       also standard Aead key types via {@code AeadConfig.registerStandardKeyTypes()}.
   *
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    AeadConfig.registerStandardKeyTypes(); // calls also MacConfig.registerStandardKeyTypes()
    registerKeyManager(new EciesAeadHkdfPublicKeyManager());
  }

  /**
   * Registers the given {@code keyManager} for the key type {@code keyManager.getKeyType()}.
   *
   * @throws GeneralSecurityException
   */
  public static void registerKeyManager(final KeyManager<HybridEncrypt> keyManager)
      throws GeneralSecurityException {
    Registry.registerKeyManager(keyManager.getKeyType(), keyManager);
  }
}
