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

import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) using PKCS1-v1_5 encoding) verifying
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1VerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  // See definitions in https://tools.ietf.org/html/rfc3447#page-43
  private static final String ASN_PREFIX_SHA256 = "3031300d060960864801650304020105000420";
  private static final String ASN_PREFIX_SHA384 = "3041300d060960864801650304020205000430";
  private static final String ASN_PREFIX_SHA512 = "3051300d060960864801650304020305000440";

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final HashType hash;

  public RsaSsaPkcs1VerifyJce(final RSAPublicKey pubKey, HashType hash)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA-PKCS1.5 in FIPS-mode, as BoringCrypto module is not available.");
    }

    Validators.validateSignatureHash(hash);
    Validators.validateRsaModulusSize(pubKey.getModulus().bitLength());
    Validators.validateRsaPublicExponent(pubKey.getPublicExponent());
    this.publicKey = pubKey;
    this.hash = hash;
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    // The algorithm is described at (https://tools.ietf.org/html/rfc8017#section-8.2). As signature
    // verification is a public operation,  throwing different exception messages doesn't give
    // attacker any useful information.
    BigInteger e = publicKey.getPublicExponent();
    BigInteger n = publicKey.getModulus();
    int nLengthInBytes = (n.bitLength() + 7) / 8;

    // Step 1. Length checking.
    if (nLengthInBytes != signature.length) {
      throw new GeneralSecurityException("invalid signature's length");
    }

    // Step 2. RSA verification.
    BigInteger s = SubtleUtil.bytes2Integer(signature);
    if (s.compareTo(n) >= 0) {
      throw new GeneralSecurityException("signature out of range");
    }
    BigInteger m = s.modPow(e, n);
    byte[] em = SubtleUtil.integer2Bytes(m, nLengthInBytes);

    // Step 3. PKCS1 encoding.
    byte[] expectedEm = emsaPkcs1(data, nLengthInBytes, hash);

    // Step 4. Compare the results.
    if (!Bytes.equal(em, expectedEm)) {
      throw new GeneralSecurityException("invalid signature");
    }
  }

  // https://tools.ietf.org/html/rfc8017#section-9.2.
  private byte[] emsaPkcs1(byte[] m, int emLen, HashType hash) throws GeneralSecurityException {
    Validators.validateSignatureHash(hash);
    MessageDigest digest =
        EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(this.hash));
    digest.update(m);
    byte[] h = digest.digest();
    byte[] asnPrefix = toAsnPrefix(hash);
    int tLen = asnPrefix.length + h.length;
    if (emLen < tLen + 11) {
      throw new GeneralSecurityException("intended encoded message length too short");
    }
    byte[] em = new byte[emLen];
    int offset = 0;
    em[offset++] = 0x00;
    em[offset++] = 0x01;
    for (int i = 0; i < emLen - tLen - 3; i++) {
      em[offset++] = (byte) 0xff;
    }
    em[offset++] = 0x00;
    System.arraycopy(asnPrefix, 0, em, offset, asnPrefix.length);
    System.arraycopy(h, 0, em, offset + asnPrefix.length, h.length);
    return em;
  }

  private byte[] toAsnPrefix(HashType hash) throws GeneralSecurityException {
    switch (hash) {
      case SHA256:
        return Hex.decode(ASN_PREFIX_SHA256);
      case SHA384:
        return Hex.decode(ASN_PREFIX_SHA384);
      case SHA512:
        return Hex.decode(ASN_PREFIX_SHA512);
      default:
        throw new GeneralSecurityException("Unsupported hash " + hash);
    }
  }
}
