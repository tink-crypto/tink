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
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;

/**
 * ECDSA verifying with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaVerifyJce implements PublicKeyVerify {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final ECPublicKey publicKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  public EcdsaVerifyJce(final ECPublicKey pubKey, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto is not available.");
    }

    EllipticCurves.checkPublicKey(pubKey);
    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.publicKey = pubKey;
    this.encoding = encoding;
  }

  @Override
  public void verify(final byte[] signature, final byte[] data) throws GeneralSecurityException {
    byte[] derSignature = signature;
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = publicKey.getParams().getCurve();
      if (signature.length != 2 * EllipticCurves.fieldSizeInBytes(curve)) {
        throw new GeneralSecurityException("Invalid signature");
      }
      derSignature = EllipticCurves.ecdsaIeee2Der(signature);
    }
    if (!EllipticCurves.isValidDerEncoding(derSignature)) {
      throw new GeneralSecurityException("Invalid signature");
    }
    Signature verifier = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean verified = false;
    try {
      verified = verifier.verify(derSignature);
    } catch (java.lang.RuntimeException ex) {
      verified = false;
    }
    if (!verified) {
      throw new GeneralSecurityException("Invalid signature");
    }
  }
}
