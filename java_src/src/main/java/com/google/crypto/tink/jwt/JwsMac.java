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

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Interface for JSON Web Signature (JWS) Message Authentication Code (MAC), as described in RFC
 * 7515.
 *
 * <h3>Security guarantees: similar to {@link com.google.crypto.tink.Mac}.</h3>
 */
@Immutable
public interface JwsMac {
  /** Computes a MAC over a JWT and and encodes it in JWS compact serialization format. */
  String computeMac(Jwt token) throws GeneralSecurityException;

  /**
   * Verifies and decodes a JWT in JWS compact serialization format.
   *
   * <p>The decoded JWT is expected to contains the headers and claims in {@code expectedJwt}. For
   * example, if {@code expectedJwt} contains an {@code iss} claim, the decoded JWT must contain an
   * identical claim. {@code expectedJwt} can contain custom claims. If a header or a claim is
   * present in {@code expectedJwt}, the decoded JWT must also contain the same header or claim.
   *
   * <p>If the decoded JWT contains timestamp claims such as {@code exp}, {@code iat} or {@code
   * nbf}, they will also be validated.
   */
  Jwt verifyMac(String compact, Jwt expectedJwt) throws GeneralSecurityException;
}
