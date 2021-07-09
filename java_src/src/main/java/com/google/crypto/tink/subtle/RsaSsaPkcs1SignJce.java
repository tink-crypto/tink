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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * RsaSsaPkcs1 (i.e. RSA Signature Schemes with Appendix (SSA) with PKCS1-v1_5 encoding) signing
 * with JCE.
 */
@Immutable
public final class RsaSsaPkcs1SignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final RSAPrivateCrtKey privateKey;

  @SuppressWarnings("Immutable")
  private final RSAPublicKey publicKey;

  private final String signatureAlgorithm;

  public RsaSsaPkcs1SignJce(final RSAPrivateCrtKey priv, HashType hash)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use RSA PKCS1.5 in FIPS-mode, as BoringCrypto module is not available.");
    }

    Validators.validateSignatureHash(hash);
    Validators.validateRsaModulusSize(priv.getModulus().bitLength());
    Validators.validateRsaPublicExponent(priv.getPublicExponent());
    this.privateKey = priv;
    this.signatureAlgorithm = SubtleUtil.toRsaSsaPkcs1Algo(hash);
    KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    this.publicKey =
        (RSAPublicKey)
            kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    Signature signer = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(data);
    byte[] signature = signer.sign();
    // Verify the signature to prevent against faulty signature computation.
    Signature verifier = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    if (!verifier.verify(signature)) {
      throw new java.lang.RuntimeException("Security bug: RSA signature computation error");
    }
    return signature;
  }
}
