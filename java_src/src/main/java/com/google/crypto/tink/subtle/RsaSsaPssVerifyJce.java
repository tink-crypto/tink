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

import static com.google.crypto.tink.internal.Util.isPrefix;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.internal.EnumTypeProtoConverter;
import com.google.crypto.tink.signature.RsaSsaPssParameters;
import com.google.crypto.tink.signature.RsaSsaPssPublicKey;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * RsaSsaPss (i.e. RSA Signature Schemes with Appendix (SSA) using PSS encoding) verifying with JCE.
 */
@Immutable
public final class RsaSsaPssVerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  // This converter is not used with a proto but rather with an ordinary enum type.
  static final EnumTypeProtoConverter<HashType, RsaSsaPssParameters.HashType> HASH_TYPE_CONVERTER =
      EnumTypeProtoConverter.<HashType, RsaSsaPssParameters.HashType>builder()
          .add(HashType.SHA256, RsaSsaPssParameters.HashType.SHA256)
          .add(HashType.SHA384, RsaSsaPssParameters.HashType.SHA384)
          .add(HashType.SHA512, RsaSsaPssParameters.HashType.SHA512)
          .build();

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final HashType sigHash;
  private final HashType mgf1Hash;
  private final int saltLength;

  @SuppressWarnings("Immutable")
  private final byte[] outputPrefix;

  @SuppressWarnings("Immutable")
  private final byte[] messageSuffix;

  @AccessesPartialKey
  public static PublicKeyVerify create(RsaSsaPssPublicKey key) throws GeneralSecurityException {

    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            kf.generatePublic(
                new RSAPublicKeySpec(key.getModulus(), key.getParameters().getPublicExponent()));
    RsaSsaPssParameters params = key.getParameters();
    return new RsaSsaPssVerifyJce(
        publicKey,
        HASH_TYPE_CONVERTER.toProtoEnum(params.getSigHashType()),
        HASH_TYPE_CONVERTER.toProtoEnum(params.getMgf1HashType()),
        params.getSaltLengthBytes(),
        key.getOutputPrefix().toByteArray(),
        key.getParameters().getVariant().equals(RsaSsaPssParameters.Variant.LEGACY)
            ? new byte[] {0}
            : new byte[0]);
  }

  public RsaSsaPssVerifyJce(
      final RSAPublicKey pubKey, HashType sigHash, HashType mgf1Hash, int saltLength)
      throws GeneralSecurityException {
    this(pubKey, sigHash, mgf1Hash, saltLength, new byte[0], new byte[0]);
  }

  private RsaSsaPssVerifyJce(
      final RSAPublicKey pubKey,
      HashType sigHash,
      HashType mgf1Hash,
      int saltLength,
      byte[] outputPrefix,
      byte[] messageSuffix)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA PSS in FIPS-mode, as BoringCrypto module is not available.");
    }

    Validators.validateSignatureHash(sigHash);
    Validators.validateRsaModulusSize(pubKey.getModulus().bitLength());
    Validators.validateRsaPublicExponent(pubKey.getPublicExponent());
    this.publicKey = pubKey;
    this.sigHash = sigHash;
    this.mgf1Hash = mgf1Hash;
    this.saltLength = saltLength;
    this.outputPrefix = outputPrefix;
    this.messageSuffix = messageSuffix;
  }

  private void noPrefixVerify(final byte[] signature, final byte[] data)
      throws GeneralSecurityException {
    // The algorithm is described at (https://tools.ietf.org/html/rfc8017#section-8.1.2). As
    // signature verification is a public operation,  throwing different exception messages doesn't
    // give attacker any useful information.
    BigInteger e = publicKey.getPublicExponent();
    BigInteger n = publicKey.getModulus();
    int nLengthInBytes = (n.bitLength() + 7) / 8;
    int mLen = (n.bitLength() - 1 + 7) / 8;

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
    byte[] em = SubtleUtil.integer2Bytes(m, mLen);

    // Step 3. PSS encoding verification.
    emsaPssVerify(data, em, n.bitLength() - 1);
  }

  // https://tools.ietf.org/html/rfc8017#section-9.1.2.
  private void emsaPssVerify(byte[] m, byte[] em, int emBits) throws GeneralSecurityException {
    // Step 1. Length checking.
    // This step is unnecessary because Java's byte[] only supports up to 2^31 -1 bytes while the
    // input limitation for the hash function is far larger (2^61 - 1 for SHA-1).

    // Step 2. Compute hash.
    Validators.validateSignatureHash(sigHash);
    MessageDigest digest =
        EngineFactory.MESSAGE_DIGEST.getInstance(SubtleUtil.toDigestAlgo(this.sigHash));
    byte[] mHash = digest.digest(m);
    int hLen = digest.getDigestLength();

    int emLen = em.length;

    // Step 3. Check emLen.
    if (emLen < hLen + this.saltLength + 2) {
      throw new GeneralSecurityException("inconsistent");
    }

    // Step 4. Check right most byte of EM.
    if (em[em.length - 1] != (byte) 0xbc) {
      throw new GeneralSecurityException("inconsistent");
    }

    // Step 5. Extract maskedDb and H from EM.
    byte[] maskedDb = Arrays.copyOf(em, emLen - hLen - 1);
    byte[] h = Arrays.copyOfRange(em, maskedDb.length, maskedDb.length + hLen);

    // Step 6. Check whether the leftmost 8 * emLen - emBits bits of the leftmost octet in maskedDB
    // are all zeros.
    for (int i = 0; i < (long) emLen * 8 - emBits; i++) {
      int bytePos = i / 8;
      int bitPos = 7 - i % 8;
      if (((maskedDb[bytePos] >> bitPos) & 1) != 0) {
        throw new GeneralSecurityException("inconsistent");
      }
    }

    // Step 7. Compute dbMask.
    byte[] dbMask = SubtleUtil.mgf1(h, emLen - hLen - 1, mgf1Hash);

    // Step 8. Compute db.
    byte[] db = new byte[dbMask.length];
    for (int i = 0; i < db.length; i++) {
      db[i] = (byte) (dbMask[i] ^ maskedDb[i]);
    }

    // Step 9. Set the leftmost 8*emLen - emBits bits of the leftmost octet in DB to zero.
    for (int i = 0; i <= (long) emLen * 8 - emBits; i++) {
      int bytePos = i / 8;
      int bitPos = 7 - i % 8;
      db[bytePos] = (byte) (db[bytePos] & ~(1 << bitPos));
    }

    // Step 10. Check db.
    for (int i = 0; i < emLen - hLen - this.saltLength - 2; i++) {
      if (db[i] != 0) {
        throw new GeneralSecurityException("inconsistent");
      }
    }
    if (db[emLen - hLen - this.saltLength - 2] != (byte) 0x01) {
      throw new GeneralSecurityException("inconsistent");
    }

    // Step 11. Extract salt from db.
    byte[] salt = Arrays.copyOfRange(db, db.length - this.saltLength, db.length);

    // Step 12. Generate M'.
    byte[] mPrime = new byte[8 + hLen + this.saltLength];
    System.arraycopy(mHash, 0, mPrime, 8, mHash.length);
    System.arraycopy(salt, 0, mPrime, 8 + hLen, salt.length);

    // Step 13. Compute H'
    byte[] hPrime = digest.digest(mPrime);
    if (!Bytes.equal(hPrime, h)) {
      throw new GeneralSecurityException("inconsistent");
    }
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    if (outputPrefix.length == 0 && messageSuffix.length == 0) {
      noPrefixVerify(signature, data);
      return;
    }
    if (!isPrefix(outputPrefix, signature)) {
      throw new GeneralSecurityException("Invalid signature (output prefix mismatch)");
    }
    byte[] dataCopy = data;
    if (messageSuffix.length != 0) {
      dataCopy = Bytes.concat(data, messageSuffix);
    }
    byte[] signatureNoPrefix = Arrays.copyOfRange(signature, outputPrefix.length, signature.length);
    noPrefixVerify(signatureNoPrefix, dataCopy);
  }
}
