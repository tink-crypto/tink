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
import com.google.crypto.tink.subtle.RsaSsaPssVerifyJce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import org.json.JSONObject;

/** An implementation of {@link JwtPublicKeyVerify} using RSA PSS. */
@Immutable
public final class JwtRsaSsaPssVerify implements JwtPublicKeyVerify {

  private final RsaSsaPssVerifyJce verifier;

  private final String algorithmName;

  public JwtRsaSsaPssVerify(RSAPublicKey publickey, String algorithm)
      throws GeneralSecurityException {
    // This function also validates the algorithm.
    Enums.HashType hash = JwtSigUtil.hashForPssAlgorithm(algorithm);
    int saltLength = JwtSigUtil.saltLengthForPssAlgorithm(algorithm);
    this.algorithmName = algorithm;
    this.verifier = new RsaSsaPssVerifyJce(publickey, hash, hash, saltLength);
  }

  @Override
  public VerifiedJwt verify(String compact, JwtValidator validator)
      throws GeneralSecurityException {
    JwtFormat.validateASCII(compact);
    String[] parts = compact.split("\\.", -1);
    if (parts.length != 3) {
      throw new JwtInvalidException(
          "only tokens in JWS compact serialization format are supported");
    }
    String unsignedCompact = parts[0] + "." + parts[1];
    byte[] expectedSignature = JwtFormat.decodeSignature(parts[2]);

    this.verifier.verify(expectedSignature, unsignedCompact.getBytes(US_ASCII));
    JwtFormat.validateHeader(this.algorithmName, JwtFormat.decodeHeader(parts[0]));
    JSONObject payload = JwtFormat.decodePayload(parts[1]);
    RawJwt token = new RawJwt.Builder(payload).build();
    return validator.validate(token);
  }
}
