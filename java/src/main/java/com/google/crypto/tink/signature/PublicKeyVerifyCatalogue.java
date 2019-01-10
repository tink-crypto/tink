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

import com.google.crypto.tink.Catalogue;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.PublicKeyVerify;
import java.security.GeneralSecurityException;

/** A catalogue of {@link PublicKeyVerify} key managers. */
class PublicKeyVerifyCatalogue implements Catalogue<PublicKeyVerify> {
  public PublicKeyVerifyCatalogue() {}

  /**
   * @return a KeyManager for the given {@code typeUrl}, {@code primitiveName} and version at least
   *     {@code minVersion} (if it exists in the catalogue).
   */
  @Override
  public KeyManager<PublicKeyVerify> getKeyManager(
      String typeUrl, String primitiveName, int minVersion) throws GeneralSecurityException {
    KeyManager<PublicKeyVerify> keyManager;
    switch (primitiveName.toLowerCase()) {
      case "publickeyverify":
        keyManager = publicKeyVerifyKeyManager(typeUrl);
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

  private KeyManager<PublicKeyVerify> publicKeyVerifyKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case EcdsaVerifyKeyManager.TYPE_URL:
        return new EcdsaVerifyKeyManager();
      case Ed25519PublicKeyManager.TYPE_URL:
        return new Ed25519PublicKeyManager();
      case RsaSsaPkcs1VerifyKeyManager.TYPE_URL:
        return new RsaSsaPkcs1VerifyKeyManager();
      case RsaSsaPssVerifyKeyManager.TYPE_URL:
        return new RsaSsaPssVerifyKeyManager();
      default:
        throw new GeneralSecurityException(
            String.format(
                "No support for primitive 'PublicKeyVerify' with key type '%s'.", typeUrl));
    }
  }

  @Override
  public PrimitiveWrapper<PublicKeyVerify> getPrimitiveWrapper() {
    return new PublicKeyVerifyWrapper();
  }
}
