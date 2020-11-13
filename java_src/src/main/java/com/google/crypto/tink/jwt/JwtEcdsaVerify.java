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

import com.google.crypto.tink.subtle.EcdsaVerifyJce;
import com.google.crypto.tink.subtle.EllipticCurves.EcdsaEncoding;
import com.google.crypto.tink.subtle.Enums;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPublicKey;

/** An implementation of {@link JwtPublicKeyVerify} using ECDSA. */
@Immutable
public final class JwtEcdsaVerify implements JwtPublicKeyVerify {

  private final EcdsaVerifyJce verifier;
  private final String algorithmName;

  public JwtEcdsaVerify(final ECPublicKey publickey, String algorithm)
      throws GeneralSecurityException {
    // This function also validates the algorithm.
    Enums.HashType hash = JwtSigUtil.hashForEcdsaAlgorithm(algorithm);
    JwtSigUtil.validateCurve(publickey.getParams().getCurve(), algorithm);
    this.algorithmName = algorithm;
    this.verifier = new EcdsaVerifyJce(publickey, hash, EcdsaEncoding.IEEE_P1363);
  }

  @Override
  public Jwt verify(String compact, JwtValidator validator) throws GeneralSecurityException {
    JwtSigUtil.validateASCII(compact);

    String[] parts = compact.split("\\.", -1);
    if (parts.length != 3) {
      throw new JwtInvalidException(
          "only tokens in JWS compact serialization format are supported");
    }
    String unsignedCompact = parts[0] + "." + parts[1];
    byte[] expectedSignature = JwtFormat.decodeSignature(parts[2]);

    this.verifier.verify(expectedSignature, unsignedCompact.getBytes(US_ASCII));
    ToBeSignedJwt token = new ToBeSignedJwt.Builder(unsignedCompact).build();
    return validator.validate(this.algorithmName, token);
  }
}
