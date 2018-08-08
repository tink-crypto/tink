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

package com.google.crypto.tink.subtle;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.Mac;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/**
 * This primitive performs an encrypt-then-Mac operation on plaintext and additional authenticated
 * data (aad).
 *
 * <p>The Mac is computed over (aad || ciphertext || size of aad), thus it doesn't violate the <a
 * href="https://en.wikipedia.org/wiki/Horton_Principle">Horton Principle</a>. This implementation
 * is based on <a
 * href="http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05">Authenticated Encryption
 * with AES-CBC and HMAC-SHA</a>.
 *
 * @since 1.0.0
 */
public final class EncryptThenAuthenticate implements Aead {
  private final IndCpaCipher cipher;
  private final Mac mac;
  private final int macLength;

  public EncryptThenAuthenticate(final IndCpaCipher cipher, final Mac mac, int macLength) {
    this.cipher = cipher;
    this.mac = mac;
    this.macLength = macLength;
  }

  /** Returns a new EncryptThenAuthenticate instance using AES-CTR and HMAC. */
  public static Aead newAesCtrHmac(
      final byte[] aesCtrKey, int ivSize, String hmacAlgorithm, final byte[] hmacKey, int tagSize)
      throws GeneralSecurityException {
    IndCpaCipher cipher = new AesCtrJceCipher(aesCtrKey, ivSize);
    SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, "HMAC");
    Mac hmac = new MacJce(hmacAlgorithm, hmacKeySpec, tagSize);
    return new EncryptThenAuthenticate(cipher, hmac, tagSize);
  }

  /**
   * Encrypts {@code plaintext} with {@code aad} as additional authenticated data. The resulting
   * ciphertext allows for checking authenticity and integrity of additional data ({@code aad}), but
   * does not guarantee its secrecy.
   *
   * <p>The plaintext is encrypted with an {@code IndCpaCipher}, then MAC is computed over (aad ||
   * ciphertext || t) where t is aad's length in bits represented as 64-bit bigendian unsigned
   * integer. The final ciphertext format is (ind-cpa ciphertext || mac).
   *
   * @return resulting ciphertext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] ciphertext = cipher.encrypt(plaintext);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] aadLengthInBits =
        Arrays.copyOf(ByteBuffer.allocate(8).putLong(8L * aad.length).array(), 8);
    byte[] macValue = mac.computeMac(Bytes.concat(aad, ciphertext, aadLengthInBits));
    return Bytes.concat(ciphertext, macValue);
  }

  /**
   * Decrypts {@code ciphertext} with {@code aad} as additional authenticated data. The decryption
   * verifies the authenticity and integrity of additional data ({@code aad}), but there are no
   * guarantees wrt. secrecy of that data.
   *
   * <p>The ciphertext format is ciphertext || mac. The MAC is verified against (aad || ciphertext||
   * t) where t is aad's length in bits represented as 64-bit bigendian unsigned integer.
   *
   * @return resulting plaintext.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < macLength) {
      throw new GeneralSecurityException("ciphertext too short");
    }
    byte[] rawCiphertext = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - macLength);
    byte[] macValue =
        Arrays.copyOfRange(ciphertext, ciphertext.length - macLength, ciphertext.length);
    byte[] aad = associatedData;
    if (aad == null) {
      aad = new byte[0];
    }
    byte[] aadLengthInBits =
        Arrays.copyOf(ByteBuffer.allocate(8).putLong(8L * aad.length).array(), 8);
    mac.verifyMac(macValue, Bytes.concat(aad, rawCiphertext, aadLengthInBits));
    return cipher.decrypt(rawCiphertext);
  }
}
