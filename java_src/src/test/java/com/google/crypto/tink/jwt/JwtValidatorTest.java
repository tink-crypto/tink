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
import static org.junit.Assert.assertThrows;

import java.security.InvalidAlgorithmParameterException;
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
  public void validate_noAlgorithm_shouldThrow() throws Exception {
    String algo = "HS256";
    JwtValidator validator = new JwtValidator.Builder().build();
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().build();

    assertThrows(IllegalStateException.class, () -> validator.validate(algo, unverified));
  }

  @Test
  public void validate_wrongAlgorithm_shouldThrow() throws Exception {
    String algo = "HS256";
    JwtValidator validator = new JwtValidator.Builder().build();
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setAlgorithm(algo).build();

    assertThrows(
        InvalidAlgorithmParameterException.class, () -> validator.validate("blah", unverified));
  }

  @Test
  public void validate_algorithm_success() throws Exception {
    String algo = "HS256";
    JwtValidator validator = new JwtValidator.Builder().build();
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setAlgorithm(algo).build();
    Jwt token = validator.validate(algo, unverified);

    assertThat(token.getAlgorithm()).isEqualTo(algo);
  }

  @Test
  public void validate_expired_shouldThrow() throws Exception {
    String algo = "HS256";
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder()
            .setAlgorithm(algo)
            .setExpiration(clock1.instant().plus(Duration.ofMinutes(1)))
            .build();

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();

    assertThrows(JwtExpiredException.class, () -> validator.validate(algo, token));
  }

  @Test
  public void validate_notExpired_success() throws Exception {
    String algo = "HS256";
    Clock clock = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    Instant expiration = clock.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setExpiration(expiration).build();
    JwtValidator validator = new JwtValidator.Builder().build();
    Jwt token = validator.validate(algo, unverified);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(expiration.getEpochSecond());
  }

  @Test
  public void validate_notExpired_clockSkew_success() throws Exception {
    String algo = "HS256";
    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minutes in the future.
    Instant expiration = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setExpiration(expiration).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = validator.validate(algo, unverified);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(expiration.getEpochSecond());
  }

  @Test
  public void validate_before_shouldThrow() throws Exception {
    String algo = "HS256";
    Clock clock = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtNotBeforeException.class, () -> validator.validate(algo, token));
  }

  @Test
  public void validate_notBefore_success() throws Exception {
    String algo = "HS256";
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();
    Jwt token = validator.validate(algo, unverified);

    assertThat(token.getNotBefore().getEpochSecond()).isEqualTo(notBefore.getEpochSecond());
  }

  @Test
  public void validate_notBefore_clockSkew_success() throws Exception {
    String algo = "HS256";
    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = validator.validate(algo, unverified);

    assertThat(token.getNotBefore().getEpochSecond()).isEqualTo(notBefore.getEpochSecond());
  }

  @Test
  public void validate_noType_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setType("JWT").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongType_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").setType("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setType("JWT").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_type_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setType("JWT").build();
    JwtValidator validator = new JwtValidator.Builder().setType("JWT").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getType()).isEqualTo("JWT");
  }

  @Test
  public void validate_noContentType_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setContentType("JWT").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongContentType_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setContentType("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setContentType("JWT").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_contentType_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setContentType("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setContentType("foo").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getContentType()).isEqualTo("foo");
  }

  @Test
  public void validate_noKeyId_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setKeyId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongKeyId_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setKeyId("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setKeyId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_keyId_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setKeyId("123").build();
    JwtValidator validator = new JwtValidator.Builder().setKeyId("123").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getKeyId()).isEqualTo("123");
  }

  @Test
  public void validate_noIssuer_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongIssuer_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setIssuer("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_issuer_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setIssuer("123").build();
    JwtValidator validator = new JwtValidator.Builder().setIssuer("123").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getIssuer()).isEqualTo("123");
  }

  @Test
  public void validate_noSubject_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongSubject_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setSubject("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_subject_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setSubject("123").build();
    JwtValidator validator = new JwtValidator.Builder().setSubject("123").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getSubject()).isEqualTo("123");
  }

  @Test
  public void validate_noJwtId_shouldThrow() throws Exception {
    ToBeSignedJwt token = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_wrongJwtId_shouldThrow() throws Exception {
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setJwtId("blah").build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", token));
  }

  @Test
  public void validate_jwtId_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").setJwtId("123").build();
    JwtValidator validator = new JwtValidator.Builder().setJwtId("123").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getJwtId()).isEqualTo("123");
  }

  @Test
  public void validate_noAudienceInJwt_shouldThrow() throws Exception {
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", unverified));
  }

  @Test
  public void validate_noAudienceInValidator_shouldThrow() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", unverified));
  }

  @Test
  public void validate_wrongAudience_shouldThrow() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();

    assertThrows(JwtInvalidException.class, () -> validator.validate("HS256", unverified));
  }

  @Test
  public void validate_audience_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void validate_multipleAudiences_success() throws Exception {
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder()
            .setAlgorithm("HS256")
            .addAudience("foo")
            .addAudience("bar")
            .build();
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();
    Jwt token = validator.validate("HS256", unverified);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }
}
