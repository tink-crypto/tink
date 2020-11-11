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
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;

/** An implementation of {@link JwtPublicKeySign} using RSA PKCS1. */
@Immutable
public final class JwtRsaSsaPkcs1Sign implements JwtPublicKeySign {

  private final RsaSsaPkcs1SignJce pks;

  private final String algorithmName;

  public JwtRsaSsaPkcs1Sign(RSAPrivateCrtKey key, String algorithm)
      throws GeneralSecurityException {
    // This function also validates the algorithm.
    Enums.HashType hash = JwtSigUtil.hashForPkcs1Algorithm(algorithm);
    this.algorithmName = algorithm;
    this.pks = new RsaSsaPkcs1SignJce(key, hash);
  }

  @Override
  public String sign(ToBeSignedJwt token) throws GeneralSecurityException {
    String unsignedCompact =
        JwtFormat.createUnsignedCompact(this.algorithmName, token.getPayload());
    return JwtFormat.createSignedCompact(
        unsignedCompact, pks.sign(unsignedCompact.getBytes(US_ASCII)));
  }
}
