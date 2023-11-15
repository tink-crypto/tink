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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Mac;
import com.google.crypto.tink.aead.AesCtrHmacAeadKey;
import com.google.crypto.tink.internal.Util;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/**
 * This primitive performs an encrypt-then-Mac operation on plaintext and associated data (ad).
 *
 * <p>The Mac is computed over (ad || ciphertext || size of ad), thus it doesn't violate the <a
 * href="https://en.wikipedia.org/wiki/Horton_Principle">Horton Principle</a>. This implementation
 * is based on <a
 * href="http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05">Authenticated Encryption
 * with AES-CBC and HMAC-SHA</a>.
 *
 * @since 1.0.0
 */
@AccessesPartialKey
public final class EncryptThenAuthenticate implements Aead {
  private final IndCpaCipher cipher;
  private final Mac mac;
  private final int macLength;
  private final byte[] outputPrefix;

  public EncryptThenAuthenticate(final IndCpaCipher cipher, final Mac mac, int macLength) {
    this(cipher, mac, macLength, new byte[] {});
  }

  private EncryptThenAuthenticate(
      IndCpaCipher cipher, Mac mac, int macLength, byte[] outputPrefix) {
    this.cipher = cipher;
    this.mac = mac;
    this.macLength = macLength;
    this.outputPrefix = outputPrefix;
  }

  /**
   * Create an AES CTR HMAC instance. This instance is *full*, meaning that, if the key is of the
   * type TINK or CRUNCHY, the ciphertexts created by this instance will be prefixed with
   * `outputPrefix` containing some important Tink metadata.
   */
  public static Aead create(AesCtrHmacAeadKey key) throws GeneralSecurityException {
    return new EncryptThenAuthenticate(
        new AesCtrJceCipher(
            key.getAesKeyBytes().toByteArray(InsecureSecretKeyAccess.get()),
            key.getParameters().getIvSizeBytes()),
        new PrfMac(
            new PrfHmacJce(
                "HMAC" + key.getParameters().getHashType(),
                new SecretKeySpec(
                    key.getHmacKeyBytes().toByteArray(InsecureSecretKeyAccess.get()), "HMAC")),
            key.getParameters().getTagSizeBytes()),
        key.getParameters().getTagSizeBytes(),
        key.getOutputPrefix().toByteArray());
  }

  /**
   * Returns a new {@code EncryptThenAuthenticate} instance using AES-CTR and HMAC. This is an older
   * method that doesn't use the new Tink keys API, thus the returned instance is not a full
   * primitive. This means that `outputPrefix` is always empty even for TINK/CRUNCHY type keys.
   */
  public static Aead newAesCtrHmac(
      final byte[] aesCtrKey, int ivSize, String hmacAlgorithm, final byte[] hmacKey, int tagSize)
      throws GeneralSecurityException {
    IndCpaCipher cipher = new AesCtrJceCipher(aesCtrKey, ivSize);
    SecretKeySpec hmacKeySpec = new SecretKeySpec(hmacKey, "HMAC");
    Mac hmac = new PrfMac(new PrfHmacJce(hmacAlgorithm, hmacKeySpec), tagSize);
    return new EncryptThenAuthenticate(cipher, hmac, tagSize);
  }

  /**
   * Encrypts {@code plaintext} with {@code associatedData}. The resulting ciphertext allows
   * for checking authenticity and integrity of associated data (ad), but does not guarantee its
   * secrecy.
   *
   * <p>The plaintext is encrypted with an {@code IndCpaCipher}, then MAC is computed over (ad ||
   * ciphertext || t) where t is ad's length in bits represented as 64-bit bigendian unsigned
   * integer. The final ciphertext format is (output prefix || ind-cpa ciphertext || mac).
   *
   * @return resulting ciphertext.
   */
  @Override
  public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
      throws GeneralSecurityException {
    byte[] ciphertext = cipher.encrypt(plaintext);
    byte[] ad = associatedData;
    if (ad == null) {
      ad = new byte[0];
    }
    byte[] adLengthInBits =
        Arrays.copyOf(ByteBuffer.allocate(8).putLong(8L * ad.length).array(), 8);
    byte[] macValue = mac.computeMac(Bytes.concat(ad, ciphertext, adLengthInBits));
    return Bytes.concat(outputPrefix, ciphertext, macValue);
  }

  /**
   * Decrypts {@code ciphertext} with {@code associatedData} as associated data. The decryption
   * verifies the authenticity and integrity of associated data (ad), but there are no guarantees
   * with respect to secrecy of that data.
   *
   * <p>The ciphertext format is output prefix || ciphertext || mac. If present, the correctness of
   * output prefix is verified. The MAC is verified against (ad || ciphertext || t) where t is ad's
   * length in bits represented as 64-bit big-endian unsigned integer.
   *
   * @return resulting plaintext.
   */
  @Override
  public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
      throws GeneralSecurityException {
    if (ciphertext.length < macLength + outputPrefix.length) {
      throw new GeneralSecurityException("Decryption failed (ciphertext too short).");
    }
    if (!Util.isPrefix(outputPrefix, ciphertext)) {
      throw new GeneralSecurityException("Decryption failed (OutputPrefix mismatch).");
    }
    byte[] rawCiphertext =
        Arrays.copyOfRange(ciphertext, outputPrefix.length, ciphertext.length - macLength);
    byte[] macValue =
        Arrays.copyOfRange(ciphertext, ciphertext.length - macLength, ciphertext.length);
    byte[] ad = associatedData;
    if (ad == null) {
      ad = new byte[0];
    }
    byte[] adLengthInBits =
        Arrays.copyOf(ByteBuffer.allocate(8).putLong(8L * ad.length).array(), 8);
    mac.verifyMac(macValue, Bytes.concat(ad, rawCiphertext, adLengthInBits));
    return cipher.decrypt(rawCiphertext);
  }
}
