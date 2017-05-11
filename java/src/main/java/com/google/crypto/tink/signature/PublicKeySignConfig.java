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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import java.security.GeneralSecurityException;

/**
 * PublicKeySignConfig offers convenience methods for initializing {@code PublicKeySignFactory}
 * and the underlying {@code Registry.INSTANCE}.  In particular, it  allows for initalizing the
 * {@code Registry} with native key types and their managers that Tink supports out of the box.
 * These key types are divided in two groups:
 *   - standard: secure and safe to use in new code. Over time, with new developments in
 *               cryptanalysis and computing power, some standard key types might become legacy.
 *   - legacy: deprecated and insecure or obsolete, should not be used in new code. Existing users
 *             should upgrade to one of the standard key types.
 * This divison allows for gradual retiring insecure or obsolete key types.
 *
 * For more information on how to obtain and use PublicKeySign primitives,
 * see {@code PublicKeySignFactory}.
 */
public final class PublicKeySignConfig {
  /**
   * Registers standard PublicKeySign key types and their managers with the {@code Registry}.
   * @throws GeneralSecurityException
   */
  public static void registerStandardKeyTypes() throws GeneralSecurityException {
    registerKeyManager(new EcdsaSignKeyManager());
    registerKeyManager(new Ed25519PrivateKeyManager());
  }

  /**
   * Registers legacy PublicKeySign key types and their managers with the {@code Registry}.
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
  public static boolean registerKeyManager(final KeyManager<PublicKeySign> keyManager)
      throws GeneralSecurityException {
    return Registry.INSTANCE.registerKeyManager(keyManager.getKeyType(), keyManager);
  }
}
