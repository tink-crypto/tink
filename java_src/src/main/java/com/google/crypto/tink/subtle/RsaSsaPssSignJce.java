// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.TinkFips;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

/**
 * RsaSsaPss (i.e. RSA Signature Schemes with Appendix (SSA) with PSS encoding) signing with JCE.
 */
@Immutable
public final class RsaSsaPssSignJce implements PublicKeySign {
  public static final TinkFips.AlgorithmFipsCompatibility FIPS =
      TinkFips.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final RSAPrivateCrtKey privateKey;

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final HashType sigHash;
  private final HashType mgf1Hash;
  private final int saltLength;
  private static final String RAW_RSA_ALGORITHM = "RSA/ECB/NOPADDING";

  public RsaSsaPssSignJce(
      final RSAPrivateCrtKey priv, HashType sigHash, HashType mgf1Hash, int saltLength)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA PSS in FIPS-mode, as BoringCrypto module is not available.");
    }

    Validators.validateSignatureHash(sigHash);
    Validators.validateRsaModulusSize(priv.getModulus().bitLength());
    Validators.validateRsaPublicExponent(priv.getPublicExponent());
    this.privateKey = priv;
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    this.publicKey =
        (RSAPublicKey)
            kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
    this.sigHash = sigHash;
    this.mgf1Hash = mgf1Hash;
    this.saltLength = saltLength;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    // https://tools.ietf.org/html/rfc8017#section-8.1.1.
    int modBits = publicKey.getModulus().bitLength();

    byte[] em = emsaPssEncode(data, modBits - 1);
    return rsasp1(em);
  }

  private byte[] rsasp1(byte[] m) throws GeneralSecurityException {
    Cipher decryptCipher = EngineFactory.CIPHER.getInstance(RAW_RSA_ALGORITHM);
    decryptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
    byte[] c = decryptCipher.doFinal(m);
    // To make sure the private key operation is correct, we check the result with public key
    // operation.
    Cipher encryptCipher = EngineFactory.CIPHER.getInstance(RAW_RSA_ALGORITHM);
    encryptCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
    byte[] m0 = encryptCipher.doFinal(c);
    if (!new BigInteger(1, m).equals(new BigInteger(1, m0))) {
      throw new java.lang.RuntimeException("Security bug: RSA signature computation error");
    }
    return c;
  }

  // https://tools.ietf.org/html/rfc8017#section-9.1.1.
  private byte[] emsaPssEncode(byte[] m, int emBits) throws GeneralSecurityException {
    // Step 1. Length checking.
    // This step is unnecessary because Java's byte[] only supports up to 2^31 -1 bytes while the
    // input limitation for the hash function is far larger (2^61 - 1 for SHA-1).

    // Step 2. Compute hash.
    Validators.validateSignatureHash(sigHash);
    MessageDigest digest =
        EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(this.sigHash));
    byte[] mHash = digest.digest(m);

    // Step 3. Check emLen.
    int hLen = digest.getDigestLength();
    int emLen = (emBits - 1) / 8 + 1;
    if (emLen < hLen + this.saltLength + 2) {
      throw new GeneralSecurityException("encoding error");
    }

    // Step 4. Generate random salt.
    byte[] salt = Random.randBytes(this.saltLength);

    // Step 5. Compute M'.
    byte[] mPrime = new byte[8 + hLen + this.saltLength];
    System.arraycopy(mHash, 0, mPrime, 8, hLen);
    System.arraycopy(salt, 0, mPrime, 8 + hLen, salt.length);

    // Step 6. Compute H.
    byte[] h = digest.digest(mPrime);

    // Step 7, 8. Generate DB.
    byte[] db = new byte[emLen - hLen - 1];
    db[emLen - this.saltLength - hLen - 2] = (byte) 0x01;
    System.arraycopy(salt, 0, db, emLen - this.saltLength - hLen - 1, salt.length);

    // Step 9. Compute dbMask.
    byte[] dbMask = SubtleUtil.mgf1(h, emLen - hLen - 1, this.mgf1Hash);

    // Step 10. Compute maskedDb.
    byte[] maskedDb = new byte[emLen - hLen - 1];
    for (int i = 0; i < maskedDb.length; i++) {
      maskedDb[i] = (byte) (db[i] ^ dbMask[i]);
    }

    // Step 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in maskedDB to zero.
    for (int i = 0; i < (long) emLen * 8 - emBits; i++) {
      int bytePos = i / 8;
      int bitPos = 7 - i % 8;
      maskedDb[bytePos] = (byte) (maskedDb[bytePos] & ~(1 << bitPos));
    }

    // Step 12. Generate EM.
    byte[] em = new byte[maskedDb.length + hLen + 1];
    System.arraycopy(maskedDb, 0, em, 0, maskedDb.length);
    System.arraycopy(h, 0, em, maskedDb.length, h.length);
    em[maskedDb.length + hLen] = (byte) 0xbc;
    return em;
  }
}
