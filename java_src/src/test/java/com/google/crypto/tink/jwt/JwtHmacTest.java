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

import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.testing.TestUtil;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JwtHmac */
@RunWith(JUnit4.class)
public final class JwtHmacTest {

  @Test
  public void constructor_keySizeIsTooSmall_shouldThrow() throws Exception {
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> new JwtHmac("HS256", new SecretKeySpec(Random.randBytes(31), "HMAC")));
  }

  @Test
  public void constructor_invalidAlgorithm_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new JwtHmac("blah", new SecretKeySpec(Random.randBytes(32), "HMAC")));
  }

  @Test
  public void computeVerifyMac_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    String type = "JWT";
    String issuer = "google";
    String audience = "mybank";
    String jwtId = "user123";
    double amount = 0.1;
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder()
            .setType(type)
            .setIssuer(issuer)
            .addAudience(audience)
            .setJwtId(jwtId)
            .addClaim("amount", amount)
            .build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().setAudience(audience).build();
    Jwt token = mac.verifyCompact(compact, validator);
    double value = (double) token.getClaim("amount");

    assertThat(value).isEqualTo(amount);
    assertThat(token.getAlgorithm()).isEqualTo(algo);
    assertThat(token.getType()).isEqualTo(type);
    assertThat(token.getIssuer()).isEqualTo(issuer);
    assertThat(token.getAudiences()).containsExactly(audience);
    assertThat(token.getJwtId()).isEqualTo(jwtId);
  }

  @Test
  public void verifyCompact_modifiedHeader_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    String type = "JWT";
    String jwtId = "user123";
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setType(type).setJwtId(jwtId).build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] header = Base64.urlSafeDecode(parts[0]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(header)) {
      String modifiedHeader = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = modifiedHeader + "." + parts[1] + "." + parts[2];

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyCompact(modifiedToken, validator));
    }
  }

  @Test
  public void verifyCompact_modifiedPayload_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    String type = "JWT";
    String jwtId = "user123";
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setType(type).setJwtId(jwtId).build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] payload = Base64.urlSafeDecode(parts[1]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(payload)) {
      String modifiedPayload = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = parts[0] + "." + modifiedPayload + "." + parts[2];

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyCompact(modifiedToken, validator));
    }
  }

  @Test
  public void verifyCompact_modifiedSignature_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    String type = "JWT";
    String jwtId = "user123";
    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setType(type).setJwtId(jwtId).build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().build();

    String[] parts = compact.split("\\.", -1);
    byte[] signature = Base64.urlSafeDecode(parts[1]);

    for (TestUtil.BytesMutation mutation : TestUtil.generateMutations(signature)) {
      String modifiedSignature = Base64.urlSafeEncode(mutation.value);
      String modifiedToken = parts[0] + "." + parts[1] + "." + modifiedSignature;

      assertThrows(
          GeneralSecurityException.class, () -> mac.verifyCompact(modifiedToken, validator));
    }
  }

  @Test
  public void verifyCompact_expired_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    ToBeSignedJwt token =
        new ToBeSignedJwt.Builder()
            .setAlgorithm(algo)
            .setExpiration(clock1.instant().plus(Duration.ofMinutes(1)))
            .build();
    String compact = mac.createCompact(token);

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();

    assertThrows(JwtExpiredException.class, () -> mac.verifyCompact(compact, validator));
  }

  @Test
  public void verifyCompact_notExpired_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock = Clock.systemUTC();
    // This token expires in 1 minute in the future.
    Instant expiration = clock.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setExpiration(expiration).build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(expiration.getEpochSecond());
  }

  @Test
  public void verifyCompact_notExpired_clockSkew_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock1 = Clock.systemUTC();
    // This token expires in 1 minutes in the future.
    Instant expiration = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setExpiration(expiration).build();
    String compact = mac.createCompact(unverified);

    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(expiration.getEpochSecond());
  }

  @Test
  public void verifyCompact_before_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    String compact = mac.createCompact(unverified);

    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtNotBeforeException.class, () -> mac.verifyCompact(compact, validator));
  }

  @Test
  public void validate_notBefore_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    String compact = mac.createCompact(unverified);

    // Move the clock to 2 minutes in the future.
    Clock clock2 = Clock.offset(clock1, Duration.ofMinutes(2));
    JwtValidator validator = new JwtValidator.Builder().setClock(clock2).build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getNotBefore().getEpochSecond()).isEqualTo(notBefore.getEpochSecond());
  }

  @Test
  public void validate_notBefore_clockSkew_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    Clock clock1 = Clock.systemUTC();
    // This token cannot be used until 1 minute in the future.
    Instant notBefore = clock1.instant().plus(Duration.ofMinutes(1));
    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm(algo).setNotBefore(notBefore).build();
    String compact = mac.createCompact(unverified);

    // A clock skew of 1 minute is allowed.
    JwtValidator validator = new JwtValidator.Builder().setClockSkew(Duration.ofMinutes(1)).build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getNotBefore().getEpochSecond()).isEqualTo(notBefore.getEpochSecond());
  }

  @Test
  public void verifyCompact_noAudienceInJwt_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    ToBeSignedJwt unverified = new ToBeSignedJwt.Builder().setAlgorithm("HS256").build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyCompact(compact, validator));
  }

  @Test
  public void verifyCompact_noAudienceInValidator_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyCompact(compact, validator));
  }

  @Test
  public void verifyCompact_wrongAudience_shouldThrow() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();

    assertThrows(JwtInvalidException.class, () -> mac.verifyCompact(compact, validator));
  }

  @Test
  public void verifyCompact_audience_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder().setAlgorithm("HS256").addAudience("foo").build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().setAudience("foo").build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void verifyCompact_multipleAudiences_success() throws Exception {
    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Random.randBytes(32), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    ToBeSignedJwt unverified =
        new ToBeSignedJwt.Builder()
            .setAlgorithm("HS256")
            .addAudience("foo")
            .addAudience("bar")
            .build();
    String compact = mac.createCompact(unverified);
    JwtValidator validator = new JwtValidator.Builder().setAudience("bar").build();
    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  // Test vectors copied from https://tools.ietf.org/html/rfc7515#appendix-A.1.
  @Test
  public void verifyCompact_rfc7515TestVector_shouldThrow() throws Exception {
    String key =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    // The sample token has expired since 2011-03-22.
    String compact =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
            + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
            + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Base64.urlSafeDecode(key), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);
    JwtValidator validator = new JwtValidator.Builder().build();

    assertThrows(JwtExpiredException.class, () -> mac.verifyCompact(compact, validator));
  }

  // Test vectors copied from https://tools.ietf.org/html/rfc7515#appendix-A.1.
  @Test
  public void verifyCompact_rfc7515TestVector_fixedClock_success() throws Exception {
    String key =
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
    // The sample token has expired since 2011-03-22T18:43:00Z.
    String compact =
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
            + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
            + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    String algo = "HS256";
    SecretKey secretKey = new SecretKeySpec(Base64.urlSafeDecode(key), "HMAC");
    JwtHmac mac = new JwtHmac(algo, secretKey);

    // One minute earlier than the expiration time of the sample token.
    String instant = "2011-03-22T18:42:00Z";
    Clock clock = Clock.fixed(Instant.parse(instant), ZoneOffset.UTC);
    JwtValidator validator = new JwtValidator.Builder().setClock(clock).build();

    Jwt token = mac.verifyCompact(compact, validator);

    assertThat(token.getAlgorithm()).isEqualTo(algo);
    assertThat(token.getType()).isEqualTo("JWT");
    assertThat(token.getIssuer()).isEqualTo("joe");
    boolean value = (boolean) token.getClaim("http://example.com/is_root");

    assertThat(value).isTrue();
  }
}
