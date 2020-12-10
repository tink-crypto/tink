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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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

  @SuppressWarnings("Immutable") // We do not mutate the payload.
  private final JSONObject payload;


  VerifiedJwt(JSONObject payload) {
    this.payload = payload;
  }

  /**
   * Returns the {@code iss} claim that identifies the principal that issued the JWT or {@code null}
   * for none.
   */
  public String getIssuer() {
    return (String) getClaimWithoutValidation(JwtNames.CLAIM_ISSUER);
  }

  /**
   * Returns the {@code sub} claim identifying the principal that is the subject of the JWT or
   * {@code null} for none.
   */
  public String getSubject() {
    return (String) getClaimWithoutValidation(JwtNames.CLAIM_SUBJECT);
  }

  /**
   * Returns the {@code aud} claim identifying the principals that are the audience of the JWT or
   * {@code null} for none.
   */
  public List<String> getAudiences() {
    JSONArray audiences = (JSONArray) getClaimWithoutValidation(JwtNames.CLAIM_AUDIENCE);
    if (audiences == null) {
      return null;
    }

    List<String> result = new ArrayList<>(audiences.length());
    for (int i = 0; i < audiences.length(); i++) {
      try {
        result.add(audiences.getString(i));
      } catch (JSONException ex) {
        throw new IllegalStateException("invalid audience", ex);
      }
    }

    return Collections.unmodifiableList(result);
  }

  /**
   * Returns the {@code jti} claim that provides a unique identifier for the JWT or {@code null} for
   * none.
   */
  public String getJwtId() {
    return (String) getClaimWithoutValidation(JwtNames.CLAIM_JWT_ID);
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
    return getInstant(JwtNames.CLAIM_EXPIRATION);
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
    return getInstant(JwtNames.CLAIM_NOT_BEFORE);
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
    return getInstant(JwtNames.CLAIM_ISSUED_AT);
  }

  /**
   * Returns the claim of name {@code name} or {@code null} for none.
   */
  public Object getClaimWithoutValidation(String name) {
    try {
      return payload.get(name);
    } catch (JSONException ex) {
      return null;
    }
  }

  /**
   * Returns the claim of name {@code name} or {@code null} for none.
   */
  public Object getClaim(String name) {
    JwtNames.validate(name);
    return getClaimWithoutValidation(name);
  }


  private Instant getInstant(String name) {
    try {
      return Instant.ofEpochSecond(payload.getLong(name));
    } catch (JSONException ex) {
      return null;
    }
  }
}
