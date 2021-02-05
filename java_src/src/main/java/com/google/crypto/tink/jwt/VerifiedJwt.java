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
import java.time.Instant;
import java.util.List;

/**
 * A read-only implementation of <a href="https://tools.ietf.org/html/rfc7519">JSON Web Token</a>
 * (JWT).
 *
 * <p>A new instance of this class is returned as the result of a sucessfully verification of a JWT.
 * @see {@link JwsMac#verifyMac}
 *
 * It contains the payload of the token, but no header information (typ, cty, alg and kid).
 */
@Immutable
public final class VerifiedJwt {

  private final RawJwt rawJwt;

  VerifiedJwt(RawJwt rawJwt) {
    this.rawJwt = rawJwt;
  }

  /**
   * Returns the {@code iss} claim that identifies the principal that issued the JWT or {@code null}
   * for none.
   */
  public String getIssuer() throws JwtInvalidException {
    return this.rawJwt.getIssuer();
  }

  /**
   * Returns the {@code sub} claim identifying the principal that is the subject of the JWT or
   * {@code null} for none.
   */
  public String getSubject() throws JwtInvalidException {
    return this.rawJwt.getSubject();
  }

  /**
   * Returns the {@code aud} claim identifying the principals that are the audience of the JWT or
   * {@code null} for none.
   */
  public List<String> getAudiences() throws JwtInvalidException {
    return this.rawJwt.getAudiences();
  }

  /**
   * Returns the {@code jti} claim that provides a unique identifier for the JWT or {@code null} for
   * none.
   */
  public String getJwtId() throws JwtInvalidException {
    return this.rawJwt.getJwtId();
  }

  /**
   * Returns the expiration time claim {@code exp} that identifies the instant on or after which the
   * token MUST NOT be accepted for processing or {@code null} for none.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getExpiration() {
    return this.rawJwt.getExpiration();
  }

  /**
   * Returns the not before claim {@code nbf} that identifies the instant before which the token
   * MUST NOT be accepted for processing or {@code null} for none.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getNotBefore() {
    return this.rawJwt.getNotBefore();
  }

  /**
   * Returns the issued at time claim {@code iat} that identifies the instant at which the JWT was
   * issued or {@code null} for none.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getIssuedAt() {
    return this.rawJwt.getIssuedAt();
  }

  /**
   * Returns the claim of name {@code name} and type Boolean or {@code null} for none. If the claim
   * with this name has another type, this method will throw an JwtInvalidException exception.
   */
  Boolean getBooleanClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getBooleanClaim(name);
  }

  /**
   * Returns the claim of name {@code name} and type Number or {@code null} for none. If the claim
   * with this name has another type, this method will throw an JwtInvalidException exception.
   */
  Double getNumberClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getNumberClaim(name);
  }

  /**
   * Returns the claim of name {@code name} and type String or {@code null} for none. If the claim
   * with this name has another type, this method will throw an JwtInvalidException exception.
   */
  String getStringClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getStringClaim(name);
  }

  /** Returns true iff there is a claim of name {@code name} and type NULL. */
  boolean isNullClaim(String name) {
    return this.rawJwt.isNullClaim(name);
  }

  /**
   * Returns the claim of name {@code name} and type JSON Object encoded in a string, or {@code
   * null} for none. If the claims with this name has another type, this method will throw an
   * JwtInvalidException exception.
   */
  String getJsonObjectClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getJsonObjectClaim(name);
  }

  /**
   * Returns the claim of name {@code name} and type JSON Array encoded in a string, or {@code null}
   * for none. If the claims with this name has another type, this method will throw an
   * JwtInvalidException exception.
   */
  String getJsonArrayClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getJsonArrayClaim(name);
  }

}
