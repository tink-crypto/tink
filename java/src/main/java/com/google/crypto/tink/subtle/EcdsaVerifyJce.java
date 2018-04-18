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

import com.google.crypto.tink.PublicKeyVerify;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

/**
 * ECDSA verifying with JCE.
 *
 * @since 1.0.0
 */
public final class EcdsaVerifyJce implements PublicKeyVerify {
  private final ECPublicKey publicKey;
  private final String signatureAlgorithm;

  public EcdsaVerifyJce(final ECPublicKey pubKey, String signatureAlgorithm)
      throws GeneralSecurityException {
    EllipticCurves.checkPublicKey(pubKey);
    this.publicKey = pubKey;
    this.signatureAlgorithm = signatureAlgorithm;
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (!isDerEncoding(signature)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    Signature verifier = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean verified = false;
    try {
      verified = verifier.verify(signature);
    } catch (java.lang.RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }

  // Validates that the signature is in DER encoding, based on
  // https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki.
  private boolean isDerEncoding(final byte[] sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S]
    // * total-length: 1-byte or 2-byte length descriptor of everything that follows.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.

    if (sig.length
        < 1 /* 0x30 */
            + 1 /* total-length */
            + 1 /* 0x02 */
            + 1 /* R-length */
            + 1 /* R */
            + 1 /* 0x02 */
            + 1 /* S-length */
            + 1 /* S */) {
      // Signature is too short.
      return false;
    }

    // Checking bytes from left to right.

    // byte #1: a signature is of type 0x30 (compound).
    if (sig[0] != 0x30) {
      return false;
    }

    // byte #2 and maybe #3: the total length of the signature.
    int totalLen = sig[1] & 0xff;
    int totalLenLen = 1; // the length of the total length field, could be 2-byte.
    if (totalLen == 129) {
      // The signature is >= 128 bytes thus total length field is in long-form encoding and occupies
      // 2 bytes.
      totalLenLen = 2;
      // byte #3 is the total length.
      totalLen = sig[2] & 0xff;
      if (totalLen < 128) {
        // Length in long-form encoding must be >= 128.
        return false;
      }
    } else if (totalLen == 128 || totalLen > 129) {
      // Impossible values for the second byte.
      return false;
    }

    // Make sure the length covers the entire sig.
    if (totalLen != sig.length - 1 - totalLenLen) {
      return false;
    }

    // Start checking R.
    // Check whether the R element is an integer.
    if (sig[1 + totalLenLen] != 0x02) {
      return false;
    }
    // Extract the length of the R element.
    int rLen = sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */] & 0xff;
    // Make sure the length of the S element is still inside the signature.
    if (1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ + rLen + 1 /* 0x02 */
        >= sig.length) {
      return false;
    }
    // Zero-length integers are not allowed for R.
    if (rLen == 0) {
      return false;
    }
    // Negative numbers are not allowed for R.
    if ((sig[3 + totalLenLen] & 0xff) >= 128) {
      return false;
    }
    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (rLen > 1 && (sig[3 + totalLenLen] == 0x00) && ((sig[4 + totalLenLen] & 0xff) < 128)) {
      return false;
    }

    // Start checking S.
    // Check whether the S element is an integer.
    if (sig[3 + totalLenLen + rLen] != 0x02) {
      return false;
    }
    // Extract the length of the S element.
    int sLen =
        sig[1 /* 0x30 */ + totalLenLen + 1 /* 0x02 */ + 1 /* rLen */ + rLen + 1 /* 0x02 */] & 0xff;
    // Verify that the length of the signature matches the sum of the length of the elements.
    if (1 /* 0x30 */
            + totalLenLen
            + 1 /* 0x02 */
            + 1 /* rLen */
            + rLen
            + 1 /* 0x02 */
            + 1 /* sLen */
            + sLen
        != sig.length) {
      return false;
    }
    // Zero-length integers are not allowed for S.
    if (sLen == 0) {
      return false;
    }
    // Negative numbers are not allowed for S.
    if ((sig[5 + totalLenLen + rLen] & 0xff) >= 128) {
      return false;
    }
    // Null bytes at the start of S are not allowed, unless S would
    // otherwise be interpreted as a negative number.
    if (sLen > 1
        && (sig[5 + totalLenLen + rLen] == 0x00)
        && ((sig[6 + totalLenLen + rLen] & 0xff) < 128)) {
      return false;
    }

    return true;
  }
}
