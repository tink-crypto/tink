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

package com.google.crypto.tink.hybrid.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.aead.subtle.AeadFactory;
import com.google.crypto.tink.subtle.Hkdf;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

/**
 * Hybrid encryption with RSA-KEM as defined in Shoup's ISO standard proposal as KEM, and AEAD as
 * DEM and HKDF as KDF.
 *
 * <p>Shoup's ISO standard proposal is available at https://www.shoup.net/iso/std6.pdf.
 */
public final class RsaKemHybridEncrypt implements HybridEncrypt {
  private final RSAPublicKey recipientPublicKey;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final AeadFactory aeadFactory;

  public RsaKemHybridEncrypt(
      final RSAPublicKey recipientPublicKey,
      String hkdfHmacAlgo,
      final byte[] hkdfSalt,
      AeadFactory aeadFactory)
      throws GeneralSecurityException {
    RsaKem.validateRsaModulus(recipientPublicKey.getModulus());
    this.recipientPublicKey = recipientPublicKey;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.hkdfSalt = hkdfSalt;
    this.aeadFactory = aeadFactory;
  }

  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] contextInfo)
      throws GeneralSecurityException {
    // KEM: generate a random shared secret whose bit length is equal to the modulus'.
    BigInteger mod = recipientPublicKey.getModulus();
    byte[] sharedSecret = RsaKem.generateSecret(mod);

    // KEM: encrypt the shared secret using the public key.
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rsaCipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
    byte[] token = rsaCipher.doFinal(sharedSecret);

    // KDF: derive a DEM key from the shared secret, salt, and contextInfo.
    byte[] demKey =
        Hkdf.computeHkdf(
            hkdfHmacAlgo, sharedSecret, hkdfSalt, contextInfo, aeadFactory.getKeySizeInBytes());

    Aead aead = aeadFactory.createAead(demKey);
    byte[] ciphertext = aead.encrypt(plaintext, RsaKem.EMPTY_AAD);
    return ByteBuffer.allocate(token.length + ciphertext.length).put(token).put(ciphertext).array();
  }
}
