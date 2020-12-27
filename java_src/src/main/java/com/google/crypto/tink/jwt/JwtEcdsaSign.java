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
package com.google.crypto.tink.jwt;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.subtle.EcdsaSignJce;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;

/** An implementation of {@link JwtPublicKeySign} using ECDSA. */
@Immutable
public final class JwtEcdsaSign implements JwtPublicKeySign {

  private final EcdsaSignJce signer;
  private final String algorithmName;

  public JwtEcdsaSign(final ECPrivateKey privatekey, String algorithm)
      throws GeneralSecurityException {

    // This function also validates the algorithm.
    Enums.HashType hash = JwtSigUtil.hashForEcdsaAlgorithm(algorithm);
    JwtSigUtil.validateCurve(privatekey.getParams().getCurve(), algorithm);
    this.algorithmName = algorithm;
    this.signer = new EcdsaSignJce(privatekey, hash, EcdsaEncoding.IEEE_P1363);
  }

  @Override
  public String sign(RawJwt token) throws GeneralSecurityException {
    String unsignedCompact =
        JwtFormat.createUnsignedCompact(this.algorithmName, token.getPayload());
    return JwtFormat.createSignedCompact(
        unsignedCompact, this.signer.sign(unsignedCompact.getBytes(US_ASCII)));
  }
}
