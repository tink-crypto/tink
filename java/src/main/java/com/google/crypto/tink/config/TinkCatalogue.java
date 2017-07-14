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

package com.google.crypto.tink.config;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.aead.AesCtrHmacAeadKeyManager;
import com.google.crypto.tink.aead.AesEaxKeyManager;
import com.google.crypto.tink.aead.AesGcmKeyManager;
import com.google.crypto.tink.aead.ChaCha20Poly1305KeyManager;
import com.google.crypto.tink.hybrid.EciesAeadHkdfPrivateKeyManager;
import com.google.crypto.tink.hybrid.EciesAeadHkdfPublicKeyManager;
import com.google.crypto.tink.mac.HmacKeyManager;
import com.google.crypto.tink.signature.EcdsaSignKeyManager;
import com.google.crypto.tink.signature.EcdsaVerifyKeyManager;
import com.google.crypto.tink.signature.Ed25519PrivateKeyManager;
import com.google.crypto.tink.signature.Ed25519PublicKeyManager;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKeyManager;
import java.security.GeneralSecurityException;

/**
 * A catalogue of key managers.
 */
public class TinkCatalogue implements Catalogue {
  public TinkCatalogue() {}

  /**
   * @return a KeyManager for the given {@code typeUrl}, {@code primitiveName} and version
   * at least {@code minVersion} (if it exists in the catalogue).
   */
  @Override
  @SuppressWarnings("rawtypes")
  public KeyManager getKeyManager(String typeUrl, String primitiveName, int minVersion)
      throws GeneralSecurityException {
    KeyManager keyManager;
    switch (primitiveName.toLowerCase()) {
      case "aead":
        keyManager = aeadKeyManager(typeUrl);
        break;
      case "hybriddecrypt":
        keyManager = hybridDecryptKeyManager(typeUrl);
        break;
      case "hybridencrypt":
        keyManager = hybridEncryptKeyManager(typeUrl);
        break;
      case "mac":
        keyManager = macKeyManager(typeUrl);
        break;
      case "publickeysign":
        keyManager = publicKeySignKeyManager(typeUrl);
        break;
      case "publickeyverify":
        keyManager = publicKeyVerifyKeyManager(typeUrl);
        break;
      case "streamingaead":
        keyManager = streamingAeadKeyManager(typeUrl);
        break;
      default:
        throw new GeneralSecurityException(
            String.format("No support for primitive '%s'.", primitiveName));
    }
    if (keyManager.getVersion() < minVersion) {
      throw new GeneralSecurityException(String.format(
          "No key manager for key type '%s' with version at least %d.", typeUrl, minVersion));
    }
    return keyManager;
  }

  private KeyManager<Aead> aeadKeyManager(String typeUrl) throws GeneralSecurityException {
    switch (typeUrl) {
      case AesCtrHmacAeadKeyManager.TYPE_URL:
        return new AesCtrHmacAeadKeyManager();
      case AesEaxKeyManager.TYPE_URL:
        return new AesEaxKeyManager();
      case AesGcmKeyManager.TYPE_URL:
        return new AesGcmKeyManager();
      case ChaCha20Poly1305KeyManager.TYPE_URL:
        return new ChaCha20Poly1305KeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'Aead' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<HybridEncrypt> hybridEncryptKeyManager(String typeUrl)
      throws GeneralSecurityException{
    switch (typeUrl) {
      case EciesAeadHkdfPublicKeyManager.TYPE_URL:
        return new EciesAeadHkdfPublicKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'HybridEncrypt' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<HybridDecrypt> hybridDecryptKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case EciesAeadHkdfPrivateKeyManager.TYPE_URL:
        return new EciesAeadHkdfPrivateKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'HybridDecrypt' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<Mac> macKeyManager(String typeUrl) throws GeneralSecurityException {
    switch (typeUrl) {
      case HmacKeyManager.TYPE_URL:
        return new HmacKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'Mac' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<PublicKeySign> publicKeySignKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case EcdsaSignKeyManager.TYPE_URL:
        return new EcdsaSignKeyManager();
      case Ed25519PrivateKeyManager.TYPE_URL:
        return new Ed25519PrivateKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'PublicKeySign' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<PublicKeyVerify> publicKeyVerifyKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case EcdsaVerifyKeyManager.TYPE_URL:
        return new EcdsaVerifyKeyManager();
      case Ed25519PublicKeyManager.TYPE_URL:
        return new Ed25519PublicKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'PublicKeyVerify' with key type '%s'.", typeUrl));
    }
  }

  private KeyManager<StreamingAead> streamingAeadKeyManager(String typeUrl)
      throws GeneralSecurityException {
    switch (typeUrl) {
      case AesGcmHkdfStreamingKeyManager.TYPE_URL:
        return new AesGcmHkdfStreamingKeyManager();
      default:
        throw new GeneralSecurityException(String.format(
            "No support for primitive 'StreamingAead' with key type '%s'.", typeUrl));
    }
  }
}
