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
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.aead.subtle.AeadFactory;
import com.google.crypto.tink.subtle.Hkdf;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.Cipher;

/**
 * Hybrid encryption with RSA-KEM as defined in Shoup's ISO standard proposal as KEM, and AEAD as
 * DEM and HKDF as KDF.
 *
 * <p>Shoup's ISO standard proposal is available at https://www.shoup.net/iso/std6.pdf.
 */
public final class RsaKemHybridDecrypt implements HybridDecrypt {
  private final RSAPrivateKey recipientPrivateKey;
  private final String hkdfHmacAlgo;
  private final byte[] hkdfSalt;
  private final AeadFactory aeadFactory;

  public RsaKemHybridDecrypt(
      final RSAPrivateKey recipientPrivateKey,
      String hkdfHmacAlgo,
      final byte[] hkdfSalt,
      AeadFactory aeadFactory)
      throws GeneralSecurityException {
    RsaKem.validateRsaModulus(recipientPrivateKey.getModulus());
    this.recipientPrivateKey = recipientPrivateKey;
    this.hkdfSalt = hkdfSalt;
    this.hkdfHmacAlgo = hkdfHmacAlgo;
    this.aeadFactory = aeadFactory;
  }

  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] contextInfo)
      throws GeneralSecurityException {
    int modSizeInBytes = RsaKem.bigIntSizeInBytes(recipientPrivateKey.getModulus());
    if (ciphertext.length < modSizeInBytes) {
      throw new GeneralSecurityException(
          String.format(
              "Ciphertext must be of at least size %d bytes, but got %d",
              modSizeInBytes, ciphertext.length));
    }

    // Decrypt the token to obtain the raw shared secret.
    ByteBuffer cipherBuffer = ByteBuffer.wrap(ciphertext);
    byte[] token = new byte[modSizeInBytes];
    cipherBuffer.get(token);
    Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
    rsaCipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey);
    byte[] sharedSecret = rsaCipher.doFinal(token);

    // KDF: derive a DEM key from the shared secret, salt, and contextInfo.
    byte[] demKey =
        Hkdf.computeHkdf(
            hkdfHmacAlgo, sharedSecret, hkdfSalt, contextInfo, aeadFactory.getKeySizeInBytes());

    // DEM: decrypt the payload.
    Aead aead = aeadFactory.createAead(demKey);
    byte[] demPayload = new byte[cipherBuffer.remaining()];
    cipherBuffer.get(demPayload);
    return aead.decrypt(demPayload, RsaKem.EMPTY_AAD);
  }
}
