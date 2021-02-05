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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;

/** A set of expected claims and headers to validate against another JWT. */
@Immutable
public final class JwtValidator {
  private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(10);

  @SuppressWarnings("Immutable") // We do not mutate the payload.
  private final JSONObject payload;

  @SuppressWarnings("Immutable") // We do not mutate the clock.
  private final Clock clock;

  private final Duration clockSkew;

  private JwtValidator(Builder builder) {
    this.payload = builder.payload;
    this.clock = builder.clock;
    this.clockSkew = builder.clockSkew;
  }

  /** Builder for JwtValidator */
  public static final class Builder {
    private final JSONObject payload;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ZERO;

    public Builder() {
      payload = new JSONObject();
    }

    private Builder setPayload(String name, Object value) {
      try {
        payload.put(name, value);
        return this;
      } catch (JSONException ex) {
        throw new IllegalArgumentException(ex);
      }
    }

    /**
     * Sets the expected issuer claim.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder setIssuer(String value) {
      return setPayload(JwtNames.CLAIM_ISSUER, value);
    }

    /**
     * Sets the expected subject claim.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public Builder setSubject(String value) {
      return setPayload(JwtNames.CLAIM_SUBJECT, value);
    }

    /**
     * Sets the expected audience claim.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public Builder setAudience(String value) {
      return setPayload(JwtNames.CLAIM_AUDIENCE, value);
    }

    /**
     * Sets the expected JWT ID claim.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public Builder setJwtId(String value) {
      return setPayload(JwtNames.CLAIM_JWT_ID, value);
    }

    /** Sets the clock used to verify timestamp claims. */
    public Builder setClock(java.time.Clock clock) {
      this.clock = clock;
      return this;
    }

    /**
     * Sets the clock skew to tolerate when verifying timestamp claims, to deal with small clock
     * differences among different machines.
     *
     * <p>As recommended by https://tools.ietf.org/html/rfc7519, the clock skew should usually be no
     * more than a few minutes. In this implementation, the maximum value is 10 minutes.
     */
    public Builder setClockSkew(Duration clockSkew) {
      if (clockSkew.compareTo(MAX_CLOCK_SKEW) > 0) {
        throw new IllegalArgumentException("Clock skew too large, max is 10 minutes");
      }
      this.clockSkew = clockSkew;
      return this;
    }

    /** Adds an arbitrary claim. */
    public Builder addClaim(String name, Object value) {
      return setPayload(JwtNames.validate(name), value);
    }

    public JwtValidator build() {
      return new JwtValidator(this);
    }
  }

  private Object getClaim(String name) {
    try {
      return payload.get(name);
    } catch (JSONException ex) {
      return null;
    }
  }

  /**
   * Validates that all claims in this validator are also present in {@code target}.
   * @throws JwtInvalidException when {@code target} contains an invalid claim or header
   */
  VerifiedJwt validate(RawJwt target) throws JwtInvalidException {
    validateTimestampClaims(target);


    Iterator<String> payloadIterator = this.payload.keys();
    while (payloadIterator.hasNext()) {
      String name = payloadIterator.next();
      if (name.equals(JwtNames.CLAIM_AUDIENCE)) {
        // This is checked below.
        continue;
      }
      Object value = target.getClaim(name);
      if (value == null || !value.equals(this.getClaim(name))) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; expected claim '%s' with value %s, but got %s",
                name, value, this.getClaim(name)));
      }
    }

    // Check that the validator's audience is in the list of claimed audiences.
    List<String> audiences = target.getAudiences();
    String audience = (String) this.getClaim(JwtNames.CLAIM_AUDIENCE);
    if ((audiences == null && audience != null)
        || (audiences != null && !audiences.contains(audience))) {
      throw new JwtInvalidException(
          String.format(
              "invalid JWT; cannot find the expected audience %s in claimed audiences %s",
              audience, audiences));
    }

    return new VerifiedJwt(target);
  }

  private void validateTimestampClaims(RawJwt target) throws JwtInvalidException {
    Instant now = this.clock.instant();

    Instant exp = target.getExpiration();
    if (exp != null && exp.isBefore(now.minus(this.clockSkew))) {
      throw new JwtInvalidException("token has expired since " + exp);
    }

    Instant nbf = target.getNotBefore();
    if (nbf != null && nbf.isAfter(now.plus(this.clockSkew))) {
      throw new JwtInvalidException("token cannot be used before " + nbf);
    }
  }
}
