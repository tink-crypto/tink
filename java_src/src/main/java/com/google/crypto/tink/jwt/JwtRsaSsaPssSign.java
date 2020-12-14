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

import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;

/** An implementation of {@link JwtPublicKeySign} using RSA PSS. */
@Immutable
public final class JwtRsaSsaPssSign implements JwtPublicKeySign {

  private final RsaSsaPssSignJce signer;

  private final String algorithmName;

  public JwtRsaSsaPssSign(RSAPrivateCrtKey key, String algorithm) throws GeneralSecurityException {
    // This function also validates the algorithm.
    Enums.HashType hash = JwtSigUtil.hashForPssAlgorithm(algorithm);
    int saltLength = JwtSigUtil.saltLengthForPssAlgorithm(algorithm);
    this.algorithmName = algorithm;
    this.signer = new RsaSsaPssSignJce(key, hash, hash, saltLength);
  }

  @Override
  public String sign(RawJwt token) throws GeneralSecurityException {
    String unsignedCompact =
        JwtFormat.createUnsignedCompact(this.algorithmName, token.getPayload());
    return JwtFormat.createSignedCompact(
        unsignedCompact, this.signer.sign(unsignedCompact.getBytes(US_ASCII)));
  }
}
