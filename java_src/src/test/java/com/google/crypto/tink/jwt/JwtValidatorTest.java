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
import static java.time.temporal.ChronoUnit.SECONDS;
import static org.junit.Assert.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JwtValidator */
@RunWith(JUnit4.class)
public final class JwtValidatorTest {

  @Test
  public void validate_expired_shouldThrow() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder()
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
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setExpiration(expiration).build();
    JwtValidator validator = new JwtValidator.Builder().build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(SECONDS));
  }

  @Test
  public void validate_notExpired_clockSkew_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minutes in the future.
    Instant expiration = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setExpiration(expiration).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getExpiration()).isEqualTo(expiration.truncatedTo(SECONDS));
  }

  @Test
  public void validate_before_shouldThrow() throws Exception {
    Clock clock = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setNotBefore(notBefore).build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_notBefore_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setNotBefore(notBefore).build();
    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(SECONDS));
  }

  @Test
  public void validate_notBefore_clockSkew_success() throws Exception {
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setNotBefore(notBefore).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getNotBefore()).isEqualTo(notBefore.truncatedTo(SECONDS));
  }

  @Test
  public void validate_noIssuer_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_wrongIssuer_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setIssuer("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_issuer_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setIssuer("123").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getIssuer()).isEqualTo("123");
  }

  @Test
  public void validate_noSubject_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_wrongSubject_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setSubject("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_subject_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setSubject("123").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getSubject()).isEqualTo("123");
  }

  @Test
  public void validate_noJwtId_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_wrongJwtId_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setJwtId("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(token));
  }

  @Test
  public void validate_jwtId_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setJwtId("123").build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getJwtId()).isEqualTo("123");
  }

  @Test
  public void validate_noAudienceInJwt_shouldThrow() throws Exception {
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void validate_noAudienceInValidator_shouldThrow() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void validate_wrongAudience_shouldThrow() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate(unverified));
  }

  @Test
  public void validate_audience_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void validate_multipleAudiences_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder()
            .addAudience("foo")
            .addAudience("bar")
            .build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();
    Jwt token = validator.validate(unverified);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }
}
