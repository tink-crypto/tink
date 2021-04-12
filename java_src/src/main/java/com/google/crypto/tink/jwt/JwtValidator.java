// Copyright 2020 Google LLC
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

package com.google.crypto.tink.jwt;

import com.google.errorprone.annotations.Immutable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/** A set of expected claims and headers to validate against another JWT. */
@Immutable
public final class JwtValidator {
  private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(10);

  private final String issuer;
  private final String subject;
  private final String audience;

  @SuppressWarnings("Immutable") // We do not mutate the clock.
  private final Clock clock;

  private final Duration clockSkew;

  private JwtValidator(Builder builder) {
    this.issuer = builder.issuer;
    this.subject = builder.subject;
    this.audience = builder.audience;
    this.clock = builder.clock;
    this.clockSkew = builder.clockSkew;
  }

  /** Builder for JwtValidator */
  public static final class Builder {
    private String issuer;
    private String subject;
    private String audience;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ZERO;

    public Builder() {
    }

    /**
     * Sets the expected issuer of the token. When this is set, all tokens with missing or different
     * {@code iss} claims are rejected.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder setIssuer(String value) {
      if (value == null) {
        throw new NullPointerException("issuer cannot be null");
      }
      this.issuer = value;
      return this;
    }

    /**
     * Sets the expected subject of the token. When this is set, all tokens with missing or
     * different {@code sub} claims are rejected.
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public Builder setSubject(String value) {
      if (value == null) {
        throw new NullPointerException("subject cannot be null");
      }
      this.subject = value;
      return this;
    }

    /**
     * Sets the expected audience. When this is set, all tokens that do not contain this audience
     * in their {@code aud} claims are rejected. If is not set, all token that have {@code aud}
     * claims are rejected. So this must be set for token that have {@code aud} claims.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public Builder setAudience(String value) {
      if (value == null) {
        throw new NullPointerException("audience cannot be null");
      }
      this.audience = value;
      return this;
    }

    /** Sets the clock used to verify timestamp claims. */
    public Builder setClock(java.time.Clock clock) {
      if (clock == null) {
        throw new NullPointerException("clock cannot be null");
      }
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

    public JwtValidator build() {
      return new JwtValidator(this);
    }
  }

  /**
   * Validates that all claims in this validator are also present in {@code target}.
   * @throws JwtInvalidException when {@code target} contains an invalid claim or header
   */
  VerifiedJwt validate(RawJwt target) throws JwtInvalidException {
    validateTimestampClaims(target);

    if (this.issuer != null) {
      if (!target.hasIssuer()) {
        throw new JwtInvalidException(
            String.format("invalid JWT; missing expected issuer %s.", this.issuer));
      }
      if (!target.getIssuer().equals(this.issuer)) {
        throw new JwtInvalidException(
            String.format("invalid JWT; expected issuer %s, but got %s", this.issuer, issuer));
      }
    }
    if (this.subject != null) {
      if (!target.hasSubject()) {
        throw new JwtInvalidException(
            String.format("invalid JWT; missing expected subject %s.", this.subject));
      }
      if (!target.getSubject().equals(this.subject)) {
        throw new JwtInvalidException(
            String.format("invalid JWT; expected subject %s, but got %s", this.subject, subject));
      }
    }
    if (this.audience != null) {
      if (!target.hasAudiences() || !target.getAudiences().contains(this.audience)) {
        throw new JwtInvalidException(
            String.format("invalid JWT; missing expected audience %s.", this.audience));
      }
    } else {
      if (target.hasAudiences()) {
        throw new JwtInvalidException("invalid JWT; token has audience set, but validator not.");
      }
    }
    return new VerifiedJwt(target);
  }

  private void validateTimestampClaims(RawJwt target) throws JwtInvalidException {
    Instant now = this.clock.instant();

    if (target.hasExpiration() && target.getExpiration().isBefore(now.minus(this.clockSkew))) {
      throw new JwtInvalidException("token has expired since " + target.getExpiration());
    }

    if (target.hasNotBefore() && target.getNotBefore().isAfter(now.plus(this.clockSkew))) {
      throw new JwtInvalidException("token cannot be used before " + target.getNotBefore());
    }
  }
}
