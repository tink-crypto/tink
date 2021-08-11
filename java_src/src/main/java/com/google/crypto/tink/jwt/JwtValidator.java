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
import java.util.Optional;

/** Defines how the headers and claims of a JWT should be validated. */
@Immutable
public final class JwtValidator {
  private static final Duration MAX_CLOCK_SKEW = Duration.ofMinutes(10);

  private final Optional<String> expectedTypeHeader;
  private final boolean ignoreTypeHeader;
  private final Optional<String> expectedIssuer;
  private final boolean ignoreIssuer;
  private final Optional<String> expectedSubject;
  private final boolean ignoreSubject;
  private final Optional<String> expectedAudience;
  private final boolean ignoreAudiences;
  private final boolean allowMissingExpiration;
  private final boolean expectIssuedInThePast;

  @SuppressWarnings("Immutable") // We do not mutate the clock.
  private final Clock clock;

  private final Duration clockSkew;

  private JwtValidator(Builder builder) {
    this.expectedTypeHeader = builder.expectedTypeHeader;
    this.ignoreTypeHeader = builder.ignoreTypeHeader;
    this.expectedIssuer = builder.expectedIssuer;
    this.ignoreIssuer = builder.ignoreIssuer;
    this.expectedSubject = builder.expectedSubject;
    this.ignoreSubject = builder.ignoreSubject;
    this.expectedAudience = builder.expectedAudience;
    this.ignoreAudiences = builder.ignoreAudiences;
    this.allowMissingExpiration = builder.allowMissingExpiration;
    this.expectIssuedInThePast = builder.expectIssuedInThePast;
    this.clock = builder.clock;
    this.clockSkew = builder.clockSkew;
  }

  /**
   * Returns a new JwtValidator.Builder.
   *
   * <p>By default, the JwtValidator requires that a token has a valid expiration claim, no issuer,
   * no subject, and no audience claim. This can be changed using the expect...(),  ignore...() and
   * allowMissingExpiration() methods.
   *
   * <p>If present, the JwtValidator also validates the not-before claim. The validation time can
   * be changed using the setClock() method.
   */
  public static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for JwtValidator */
  public static final class Builder {
    private Optional<String> expectedTypeHeader;
    private boolean ignoreTypeHeader;
    private Optional<String> expectedIssuer;
    private boolean ignoreIssuer;
    private Optional<String> expectedSubject;
    private boolean ignoreSubject;
    private Optional<String> expectedAudience;
    private boolean ignoreAudiences;
    private boolean allowMissingExpiration;
    private boolean expectIssuedInThePast;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ZERO;

    private Builder() {
      this.expectedTypeHeader = Optional.empty();
      this.ignoreTypeHeader = false;
      this.expectedIssuer = Optional.empty();
      this.ignoreIssuer = false;
      this.expectedSubject = Optional.empty();
      this.ignoreSubject = false;
      this.expectedAudience = Optional.empty();
      this.ignoreAudiences = false;
      this.allowMissingExpiration = false;
      this.expectIssuedInThePast = false;
    }

    /**
     * Sets the expected type header of the token. When this is set, all tokens with missing or
     * different {@code typ} header are rejected. When this is not set, all token that have a {@code
     * typ} header are rejected. So this must be set for token that have a {@code typ} header.
     *
     * <p>If you want to ignore the type header or if you want to validate it yourself, use
     * ignoreTypeHeader().
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder expectTypeHeader(String value) {
      if (value == null) {
        throw new NullPointerException("typ header cannot be null");
      }
      this.expectedTypeHeader = Optional.of(value);
      return this;
    }

    /** Lets the validator ignore the {@code typ} header. */
    public Builder ignoreTypeHeader() {
      this.ignoreTypeHeader = true;
      return this;
    }

    /**
     * Sets the expected issuer claim of the token. When this is set, all tokens with missing or
     * different {@code iss} claims are rejected. When this is not set, all token that have a {@code
     * iss} claim are rejected. So this must be set for token that have a {@code iss} claim.
     *
     * <p>If you want to ignore the issuer claim or if you want to validate it yourself, use
     * ignoreIssuer().
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder expectIssuer(String value) {
      if (value == null) {
        throw new NullPointerException("issuer cannot be null");
      }
      this.expectedIssuer = Optional.of(value);
      return this;
    }

    /** Lets the validator ignore the {@code iss} claim. */
    public Builder ignoreIssuer() {
      this.ignoreIssuer = true;
      return this;
    }

    /**
     * Sets the expected subject claim of the token. When this is set, all tokens with missing or
     * different {@code sub} claims are rejected. When this is not set, all token that have a {@code
     * sub} claim are rejected. So this must be set for token that have a {@code sub} claim.
     *
     * <p>If you want to ignore this claim or if you want to validate it yourself, use
     * ignoreSubject().
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public Builder expectSubject(String value) {
      if (value == null) {
        throw new NullPointerException("subject cannot be null");
      }
      this.expectedSubject = Optional.of(value);
      return this;
    }

    /** Lets the validator ignore the {@code sub} claim. */
    public Builder ignoreSubject() {
      this.ignoreSubject = true;
      return this;
    }

    /**
     * Sets the expected audience. When this is set, all tokens that do not contain this audience in
     * their {@code aud} claims are rejected. When this is not set, all token that have {@code aud}
     * claims are rejected. So this must be set for token that have {@code aud} claims.
     *
     * <p>If you want to ignore this claim or if you want to validate it yourself, use
     * ignoreAudiences().
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public Builder expectAudience(String value) {
      if (value == null) {
        throw new NullPointerException("audience cannot be null");
      }
      this.expectedAudience = Optional.of(value);
      return this;
    }

    /** Lets the validator ignore the {@code aud} claim. */
    public Builder ignoreAudiences() {
      this.ignoreAudiences = true;
      return this;
    }

    /** Checks that the {@code iat} claim is in the past.*/
    public Builder expectIssuedInThePast() {
      this.expectIssuedInThePast = true;
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

    /**
     * When set, the validator accepts tokens that do not have an expiration set.
     *
     * <p>In most cases, tokens should always have an expiration, so this option should rarely be
     * used.
     */
    public Builder allowMissingExpiration() {
      this.allowMissingExpiration = true;
      return this;
    }

    public JwtValidator build() {
      if (this.ignoreTypeHeader && this.expectedTypeHeader.isPresent()) {
        throw new IllegalArgumentException(
            "ignoreTypeHeader() and expectedTypeHeader() cannot be used together.");
      }
      if (this.ignoreIssuer && this.expectedIssuer.isPresent()) {
        throw new IllegalArgumentException(
            "ignoreIssuer() and expectedIssuer() cannot be used together.");
      }
      if (this.ignoreSubject && this.expectedSubject.isPresent()) {
        throw new IllegalArgumentException(
            "ignoreSubject() and expectedSubject() cannot be used together.");
      }
      if (this.ignoreAudiences && this.expectedAudience.isPresent()) {
        throw new IllegalArgumentException(
            "ignoreAudiences() and expectedAudience() cannot be used together.");
      }
      return new JwtValidator(this);
    }
  }

  /**
   * Validates that all claims in this validator are also present in {@code target}.
   * @throws JwtInvalidException when {@code target} contains an invalid claim or header
   */
  VerifiedJwt validate(RawJwt target) throws JwtInvalidException {
    validateTimestampClaims(target);

    if (this.expectedTypeHeader.isPresent()) {
      if (!target.hasTypeHeader()) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; missing expected type header %s.", this.expectedTypeHeader.get()));
      }
      if (!target.getTypeHeader().equals(this.expectedTypeHeader.get())) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; expected type header %s, but got %s",
                this.expectedTypeHeader.get(), target.getTypeHeader()));
      }
    } else {
      if (target.hasTypeHeader() && !this.ignoreTypeHeader) {
        throw new JwtInvalidException("invalid JWT; token has type header set, but validator not.");
      }
    }
    if (this.expectedIssuer.isPresent()) {
      if (!target.hasIssuer()) {
        throw new JwtInvalidException(
            String.format("invalid JWT; missing expected issuer %s.", this.expectedIssuer.get()));
      }
      if (!target.getIssuer().equals(this.expectedIssuer.get())) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; expected issuer %s, but got %s",
                this.expectedIssuer.get(), target.getIssuer()));
      }
    } else {
      if (target.hasIssuer() && !this.ignoreIssuer) {
        throw new JwtInvalidException("invalid JWT; token has issuer set, but validator not.");
      }
    }
    if (this.expectedSubject.isPresent()) {
      if (!target.hasSubject()) {
        throw new JwtInvalidException(
            String.format("invalid JWT; missing expected subject %s.", this.expectedSubject.get()));
      }
      if (!target.getSubject().equals(this.expectedSubject.get())) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; expected subject %s, but got %s",
                this.expectedSubject.get(), target.getSubject()));
      }
    } else {
      if (target.hasSubject() && !this.ignoreSubject) {
        throw new JwtInvalidException("invalid JWT; token has subject set, but validator not.");
      }
    }
    if (this.expectedAudience.isPresent()) {
      if (!target.hasAudiences() || !target.getAudiences().contains(this.expectedAudience.get())) {
        throw new JwtInvalidException(
            String.format(
                "invalid JWT; missing expected audience %s.", this.expectedAudience.get()));
      }
    } else {
      if (target.hasAudiences() && !this.ignoreAudiences) {
        throw new JwtInvalidException("invalid JWT; token has audience set, but validator not.");
      }
    }
    return new VerifiedJwt(target);
  }

  private void validateTimestampClaims(RawJwt target) throws JwtInvalidException {
    Instant now = this.clock.instant();

    if (!target.hasExpiration() && !this.allowMissingExpiration) {
      throw new JwtInvalidException("token does not have an expiration set");
    }

    // If expiration = now.minus(clockSkew), then the token is expired.
    if (target.hasExpiration() && !target.getExpiration().isAfter(now.minus(this.clockSkew))) {
      throw new JwtInvalidException("token has expired since " + target.getExpiration());
    }

    // If not_before = now.plus(clockSkew), then the token is fine.
    if (target.hasNotBefore() && target.getNotBefore().isAfter(now.plus(this.clockSkew))) {
      throw new JwtInvalidException("token cannot be used before " + target.getNotBefore());
    }

    // If issued_at = now.plus(clockSkew), then the token is fine.
    if (this.expectIssuedInThePast) {
      if (!target.hasIssuedAt()) {
        throw new JwtInvalidException("token does not have an iat claim");
      }
      if (target.getIssuedAt().isAfter(now.plus(this.clockSkew))) {
        throw new JwtInvalidException(
            "token has a invalid iat claim in the future: " + target.getIssuedAt());
      }
    }
  }
}
