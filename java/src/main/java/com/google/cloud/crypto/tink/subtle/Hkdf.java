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

package com.google.cloud.crypto.tink.subtle;

import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869.
 */
public class Hkdf {
  public static final String ECIES_HKDF_MAC_ALGORITHM = "HmacSha256";

  /**
   * Computes an HKDF.
   *
   * @param macAlgorithm the MAC algorithm used for computing the Hkdf. I.e., "HMACSHA1" or
   *    "HMACSHA256".
   * @param ikm the input keying material.
   * @param salt optional salt. A possibly non-secret random value. If no salt is provided
   *    (i.e. if salt has length 0) then an array of 0s of the same size as the hash digest
   *    is used as salt.
   * @param info optional context and application specific information.
   * @param size The length of the generated pseudorandom string in bytes. The maximal size is
   *    255.DigestSize, where DigestSize is the size of the underlying HMAC.
   * @return size pseudorandom bytes.
   * @throws GeneralSecurityException if the {@code macAlgorithm} is not supported or if
   *    {@code size} is too large or if {@code salt} is not a valid key for macAlgorithm (which
   *    should not happen since HMAC allows key sizes up to 2^64).
   */
  public static byte[] computeHkdf(String macAlgorithm, byte[] ikm, byte[] salt, byte[] info,
      int size) throws GeneralSecurityException {
    Mac mac = Mac.getInstance(macAlgorithm);
    if (size > 255 * mac.getMacLength()) {
      throw new GeneralSecurityException("size too large");
    }
    if (salt == null || salt.length == 0) {
      // According to RFC 5869, Section 2.2 the salt is optional. If no salt is provided
      // then HKDF uses a salt that is an array of zeros of the same length as the hash digest.
      // We do not implement this for security reasons. If an application does really not
      // want to use a salt then this should be made explicit by passing an array of 0's.
      mac.init(new SecretKeySpec(new byte[mac.getMacLength()], macAlgorithm));
    } else {
      mac.init(new SecretKeySpec(salt, macAlgorithm));
    }
    byte[] prk = mac.doFinal(ikm);
    byte[] result = new byte[size];
    int ctr = 1;
    int pos = 0;
    mac.init(new SecretKeySpec(prk, macAlgorithm));
    byte[] digest = new byte[0];
    while (true) {
      mac.update(digest);
      mac.update(info);
      mac.update((byte) ctr);
      digest = mac.doFinal();
      if (pos + digest.length < size) {
        System.arraycopy(digest, 0, result, pos, digest.length);
        pos += digest.length;
        ctr++;
      } else {
        System.arraycopy(digest, 0, result, pos, size - pos);
        break;
      }
    }
    return result;
  }


  /**
   * Computes symmetric key for ECIES with HKDF from the provided parameters.
   */
  public static byte[] computeEciesHkdfSymmetricKey(final ECPublicKey ephemeralPublicKey,
      final byte[] sharedSecret, int keySizeInBytes, final byte[] hkdfSalt, final byte[] hkdfInfo)
      throws GeneralSecurityException {
    byte[] ephemeralPublicKeyBytes = ephemeralPublicKey.getEncoded();
    byte[] hkdfInput = SubtleUtil.concat(ephemeralPublicKeyBytes, sharedSecret);
    byte[] symmetricKey = Hkdf.computeHkdf(ECIES_HKDF_MAC_ALGORITHM,
        hkdfInput, hkdfSalt, hkdfInfo, keySizeInBytes);
    return symmetricKey;
  }
}
