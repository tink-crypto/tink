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

package com.google.crypto.tink.daead;

import com.google.crypto.tink.Catalogue;
import com.google.crypto.tink.DeterministicAead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PrimitiveWrapper;
import java.security.GeneralSecurityException;

/** A catalogue of {@link DeterministicAead} key managers. */
class DeterministicAeadCatalogue implements Catalogue<DeterministicAead> {
  public DeterministicAeadCatalogue() {}

  /**
   * @return a KeyManager for the given {@code typeUrl}, {@code primitiveName} and version at least
   *     {@code minVersion} (if it exists in the catalogue).
   */
  @Override
  public KeyManager<DeterministicAead> getKeyManager(
      String typeUrl, String primitiveName, int minVersion) throws GeneralSecurityException {
    KeyManager<DeterministicAead> keyManager;
    switch (primitiveName.toLowerCase()) {
      case "deterministicaead":
        keyManager = daeadKeyManager(typeUrl);
        break;
      default:
        throw new GeneralSecurityException(
            String.format("No support for primitive '%s'.", primitiveName));
    }
    if (keyManager.getVersion() < minVersion) {
      throw new GeneralSecurityException(
          String.format(
              "No key manager for key type '%s' with version at least %d.", typeUrl, minVersion));
    }
    return keyManager;
  }

  private KeyManager<DeterministicAead> daeadKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case AesSivKeyManager.TYPE_URL:
        return new AesSivKeyManager();
      default:
        throw new GeneralSecurityException(
            String.format(
                "No support for primitive 'DeterministicAead' with key type '%s'.", typeUrl));
    }
  }

  @Override
  public PrimitiveWrapper<DeterministicAead> getPrimitiveWrapper() {
    return new DeterministicAeadWrapper();
  }
}
