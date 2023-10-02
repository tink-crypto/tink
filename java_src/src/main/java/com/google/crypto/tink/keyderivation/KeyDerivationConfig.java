// Copyright 2020 Google LLC
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

package com.google.crypto.tink.keyderivation;

import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.keyderivation.internal.PrfBasedDeriverKeyManager;
import com.google.crypto.tink.prf.HkdfPrfKeyManager;
import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link KeysetDeriver} key types supported in a particular release of Tink.
 *
 * <p>To register all {@link KeysetDeriver} key types provided in the latest Tink version one can
 * do:
 *
 * <pre>{@code
 * KeyDerivationConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of {@link KeysetDeriver}, see {@link
 * com.google.crypto.tink.KeysetHandle#getPrimitive}.
 */
public final class KeyDerivationConfig {
  /**
   * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
   * com.google.crypto.tink.KeyManager} needed to handle KeysetDeriver key types supported in Tink.
   */
  public static void register() throws GeneralSecurityException {
    // Register primitive wrappers.
    com.google.crypto.tink.keyderivation.internal.KeysetDeriverWrapper.register();

    if (TinkFips.useOnlyFips()) {
      // If Tink is built in FIPS-mode do not register algorithms which are not compatible.
      // Currently there are no FIPS-compliant key derivation primitives available, therefore no
      // key manager will be registered.
      return;
    }

    // Register required key manager for PrfBasedDeriverKeyManager.
    HkdfPrfKeyManager.register(/* newKeyAllowed= */ true);

    // Register key managers.
    PrfBasedDeriverKeyManager.register(/* newKeyAllowed= */ true);
  }

  private KeyDerivationConfig() {}
}
