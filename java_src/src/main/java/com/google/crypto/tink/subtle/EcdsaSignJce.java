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

import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums.HashType;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EllipticCurve;

/**
 * ECDSA signing with JCE.
 *
 * @since 1.0.0
 */
@Immutable
public final class EcdsaSignJce implements PublicKeySign {
  public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS =
      TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;

  @SuppressWarnings("Immutable")
  private final ECPrivateKey privateKey;

  private final String signatureAlgorithm;
  private final EcdsaEncoding encoding;

  public EcdsaSignJce(final ECPrivateKey priv, HashType hash, EcdsaEncoding encoding)
      throws GeneralSecurityException {
    if (!FIPS.isCompatible()) {
      throw new GeneralSecurityException(
          "Can not use ECDSA in FIPS-mode, as BoringCrypto is not available.");
    }

    this.privateKey = priv;
    this.signatureAlgorithm = SubtleUtil.toEcdsaAlgo(hash);
    this.encoding = encoding;
  }

  @Override
  public byte[] sign(final byte[] data) throws GeneralSecurityException {
    Signature signer = EngineFactory.SIGNATURE.getInstance(signatureAlgorithm);
    signer.initSign(privateKey);
    signer.update(data);
    byte[] signature = signer.sign();
    if (encoding == EcdsaEncoding.IEEE_P1363) {
      EllipticCurve curve = privateKey.getParams().getCurve();
      signature =
          EllipticCurves.ecdsaDer2Ieee(signature, 2 * EllipticCurves.fieldSizeInBytes(curve));
    }
    return signature;
  }
}
