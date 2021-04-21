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

import static com.google.common.truth.Truth.assertThat;
import static java.time.temporal.ChronoUnit.MILLIS;
import static org.junit.Assert.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JwtValidator */
@RunWith(JUnit4.class)
public final class JwtValidatorTest {

  @Test
  public void setNullValue_shouldThrow() throws Exception {
    assertThrows(NullPointerException.class, () -> new JwtValidator.Builder().setIssuer(null));
    assertThrows(NullPointerException.class, () -> new JwtValidator.Builder().setSubject(null));
    assertThrows(NullPointerException.class, () -> new JwtValidator.Builder().setAudience(null));
    assertThrows(NullPointerException.class, () -> new JwtValidator.Builder().setClock(null));
    assertThrows(NullPointerException.class, () -> new JwtValidator.Builder().setClockSkew(null));
  }

  @Test
  public void validate_expired_shouldThrow() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    RawJwt token =
        new RawJwt.Builder()
            .setExpiration(clock1.instant().plus(Duration.ofMinutes(1)))
            .build();

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_notExpired_success() throws Exception {
    Clock clock = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    Instant expiration = clock.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        new RawJwt.Builder().setExpiration(expiration).build();
    JwtValidator validator = new JwtValidator.Builder().build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(MILLIS));
  }

  @Test
  public void validate_notExpired_clockSkew_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minutes in the future.
    Instant expiration = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        new RawJwt.Builder().setExpiration(expiration).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(MILLIS));
  }

  @Test
  public void validate_tokenThatExpiresNow_shouldThrow() throws Exception {
    Instant expiration = Instant.ofEpochSecond(1234);
    Clock clock = Clock.fixed(expiration, ZoneOffset.UTC);
    RawJwt rawJwt =
        new RawJwt.Builder().setExpiration(expiration).build();
    JwtValidator validator = new JwtValidator.Builder().setClock(clock).build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(rawJwt));
  }

  @Test
  public void validate_before_shouldThrow() throws Exception {
    Clock clock = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock.instant().plus(Duration.ofMinutes(1));
    RawJwt token =
        new RawJwt.Builder().setNotBefore(notBefore).build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_notBefore_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        new RawJwt.Builder().setNotBefore(notBefore).build();
    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(MILLIS));
  }

  @Test
  public void validate_tokenWithNotBeforeIsNow_success() throws Exception {
    Instant notBefore = Instant.ofEpochSecond(1234);
    Clock clock = Clock.fixed(notBefore, ZoneOffset.UTC);
    RawJwt rawJwt =
        new RawJwt.Builder().setNotBefore(notBefore).build();
    JwtValidator validator = new JwtValidator.Builder().setClock(clock).build();
    VerifiedJwt token = validator.validate(rawJwt);
    assertThat(token.getNotBefore()).isEqualTo(notBefore);
  }

  @Test
  public void validate_notBefore_clockSkew_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    RawJwt unverified =
        new RawJwt.Builder().setNotBefore(notBefore).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(MILLIS));
  }

  @Test
  public void requireIssuerButNoIssuerInToken_shouldThrow() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void wrongIssuerInToken_shouldThrow() throws Exception {
    RawJwt token =
        new RawJwt.Builder().setIssuer("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void correctIssuerInToken_success() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder().setIssuer("123").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();
    VerifiedJwt token = validator.validate(unverified);
    assertThat(token.getIssuer()).isEqualTo("123");
  }

  @Test
  public void dontCheckIssuer_success() throws Exception {
    JwtValidator validator = new JwtValidator.Builder().build();

    RawJwt tokenWithIssuer = new RawJwt.Builder().setIssuer("issuer").build();
    validator.validate(tokenWithIssuer);

    RawJwt tokenWithoutIssuer = new RawJwt.Builder().build();
    validator.validate(tokenWithoutIssuer);
  }

  @Test
  public void requireSubjectButNoSubjectInToken_shouldThrow() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void wrongSubjectInToken_shouldThrow() throws Exception {
    RawJwt token =
        new RawJwt.Builder().setSubject("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void correctSubjectInToken_success() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder().setSubject("123").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getSubject()).isEqualTo("123");
  }

  @Test
  public void dontCheckSubject_success() throws Exception {
    JwtValidator validator = new JwtValidator.Builder().build();

    RawJwt tokenWithSubject = new RawJwt.Builder().setSubject("subject").build();
    validator.validate(tokenWithSubject);

    RawJwt tokenWithoutSubject = new RawJwt.Builder().build();
    validator.validate(tokenWithoutSubject);
  }

  @Test
  public void requireAudienceButNoAudienceInToken_shouldThrow() throws Exception {
    RawJwt unverified = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void audienceInTokenButNoAudienceSetInValidator_shouldThrow() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void noAudience_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().build();
    validator.validate(token);
  }

  @Test
  public void wrongAudienceInToken_shouldThrow() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void correctAudienceInToken_success() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void correctAudienceInToken2_success() throws Exception {
    RawJwt unverified =
        new RawJwt.Builder()
            .addAudience("foo")
            .addAudience("bar")
            .build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();
    VerifiedJwt token = validator.validate(unverified);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }
}
