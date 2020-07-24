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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for Jwt */
@RunWith(JUnit4.class)
public final class JwtTest {
  @Test
  public void emptyJwt_success() throws Exception {
    Jwt emptyToken = new Jwt(new JSONObject(), new JSONObject(), Clock.systemUTC(), Duration.ZERO);

    assertThat(emptyToken.getIssuer()).isNull();
    assertThat(emptyToken.getSubject()).isNull();
    assertThat(emptyToken.getAudiences()).isNull();
    assertThat(emptyToken.getJwtId()).isNull();
    assertThat(emptyToken.getExpiration()).isNull();
    assertThat(emptyToken.getNotBefore()).isNull();
    assertThat(emptyToken.getIssuedAt()).isNull();
    assertThat(emptyToken.getClaim("blah")).isNull();

    assertThrows(IllegalStateException.class, emptyToken::getAlgorithm);
    assertThat(emptyToken.getType()).isNull();
    assertThat(emptyToken.getContentType()).isNull();
    assertThat(emptyToken.getKeyId()).isNull();
  }

  @Test
  public void getIssuer_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_ISSUER, "foo");
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void getSubject_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_SUBJECT, "foo");
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void getAudiences_success() throws Exception {
    JSONObject payload = new JSONObject();
    JSONArray audiences = new JSONArray();
    audiences.put("foo");
    payload.put(JwtNames.CLAIM_AUDIENCE, audiences);
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void getMultipleAudiences_success() throws Exception {
    JSONObject payload = new JSONObject();
    JSONArray audiences = new JSONArray();
    audiences.put("foo");
    audiences.put("bar");
    payload.put(JwtNames.CLAIM_AUDIENCE, audiences);
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void getJwtId_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_JWT_ID, "foo");
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void getExpiration_success() throws Exception {
    JSONObject payload = new JSONObject();
    Instant instant = Instant.now();
    payload.put(JwtNames.CLAIM_EXPIRATION, instant.getEpochSecond());
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(instant.getEpochSecond());
  }

  @Test
  public void getNotBefore_success() throws Exception {
    JSONObject payload = new JSONObject();
    Instant instant = Instant.now();
    payload.put(JwtNames.CLAIM_NOT_BEFORE, instant.getEpochSecond());
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getNotBefore().getEpochSecond()).isEqualTo(instant.getEpochSecond());
  }

  @Test
  public void getIssuedAt_success() throws Exception {
    JSONObject payload = new JSONObject();
    Instant instant = Instant.now();
    payload.put(JwtNames.CLAIM_ISSUED_AT, instant.getEpochSecond());
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getIssuedAt().getEpochSecond()).isEqualTo(instant.getEpochSecond());
  }

  @Test
  public void getAlgorithm_success() throws Exception {
    JSONObject header = new JSONObject();
    header.put(JwtNames.HEADER_ALGORITHM, "HS256");
    Jwt token = new Jwt(header, new JSONObject(), Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getAlgorithm()).isEqualTo("HS256");
  }

  @Test
  public void getType_success() throws Exception {
    JSONObject header = new JSONObject();
    header.put(JwtNames.HEADER_TYPE, "JWT");
    Jwt token = new Jwt(header, new JSONObject(), Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getType()).isEqualTo("JWT");
  }

  @Test
  public void getContentType_success() throws Exception {
    JSONObject header = new JSONObject();
    header.put(JwtNames.HEADER_CONTENT_TYPE, "foo");
    Jwt token = new Jwt(header, new JSONObject(), Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getContentType()).isEqualTo("foo");
  }

  @Test
  public void getKeyId_success() throws Exception {
    JSONObject header = new JSONObject();
    header.put(JwtNames.HEADER_KEY_ID, "123");
    Jwt token = new Jwt(header, new JSONObject(), Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getKeyId()).isEqualTo("123");
  }

  @Test
  public void expiredToken_shouldThrow() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the expiration time to 1 minute in the past.
    Instant instant = Instant.now().minus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_EXPIRATION, instant.getEpochSecond());
    Jwt expiredToken = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThrows(JwtExpiredException.class, expiredToken::getIssuer);
    assertThrows(JwtExpiredException.class, expiredToken::getSubject);
    assertThrows(JwtExpiredException.class, expiredToken::getAudiences);
    assertThrows(JwtExpiredException.class, expiredToken::getJwtId);
    assertThrows(JwtExpiredException.class, () -> expiredToken.getClaim("blah"));
    assertThrows(JwtExpiredException.class, expiredToken::getAlgorithm);
    assertThrows(JwtExpiredException.class, expiredToken::getType);
    assertThrows(JwtExpiredException.class, expiredToken::getContentType);
    assertThrows(JwtExpiredException.class, expiredToken::getKeyId);
  }

  @Test
  public void nonExpiredToken_success() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the expiration time to 1 minute in the future.
    Instant instant = Instant.now().plus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_EXPIRATION, instant.getEpochSecond());
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(instant.getEpochSecond());

    assertThat(token.getIssuer()).isNull();
    assertThat(token.getSubject()).isNull();
    assertThat(token.getAudiences()).isNull();
    assertThat(token.getJwtId()).isNull();
    assertThat(token.getNotBefore()).isNull();
    assertThat(token.getIssuedAt()).isNull();
    assertThat(token.getClaim("blah")).isNull();

    assertThrows(IllegalStateException.class, token::getAlgorithm);
    assertThat(token.getType()).isNull();
    assertThat(token.getContentType()).isNull();
    assertThat(token.getKeyId()).isNull();
  }

  @Test
  public void expiredToken_clockSkew_success() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the expiration time to 1 minute in the past.
    Instant instant = Instant.now().minus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_EXPIRATION, instant.getEpochSecond());
    // Set the clock skew to 2 minutes.
    Jwt token = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ofMinutes(2));

    assertThat(token.getExpiration().getEpochSecond()).isEqualTo(instant.getEpochSecond());

    assertThat(token.getIssuer()).isNull();
    assertThat(token.getSubject()).isNull();
    assertThat(token.getAudiences()).isNull();
    assertThat(token.getJwtId()).isNull();
    assertThat(token.getNotBefore()).isNull();
    assertThat(token.getIssuedAt()).isNull();
    assertThat(token.getClaim("blah")).isNull();

    assertThrows(IllegalStateException.class, token::getAlgorithm);
    assertThat(token.getType()).isNull();
    assertThat(token.getContentType()).isNull();
    assertThat(token.getKeyId()).isNull();
  }

  @Test
  public void notBeforeToken_shouldThrow() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the not before time to 1 minutes in the future.
    Instant instant = Instant.now().plus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_NOT_BEFORE, instant.getEpochSecond());
    Jwt notBeforeToken = new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ZERO);

    assertThrows(JwtNotBeforeException.class, notBeforeToken::getIssuer);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getSubject);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getAudiences);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getJwtId);
    assertThrows(JwtNotBeforeException.class, () -> notBeforeToken.getClaim("blah"));
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getAlgorithm);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getType);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getContentType);
    assertThrows(JwtNotBeforeException.class, notBeforeToken::getKeyId);
  }

  @Test
  public void notBeforeToken_success() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the not before time to 1 minutes in the future.
    Instant instant = Instant.now().plus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_NOT_BEFORE, instant.getEpochSecond());
    // Move the clock to 2 minutes in the future.
    Clock clock = Clock.offset(Clock.systemUTC(), Duration.ofMinutes(2));
    Jwt notBeforeToken = new Jwt(new JSONObject(), payload, clock, Duration.ZERO);

    assertThat(notBeforeToken.getNotBefore().getEpochSecond()).isEqualTo(instant.getEpochSecond());

    assertThat(notBeforeToken.getIssuer()).isNull();
    assertThat(notBeforeToken.getSubject()).isNull();
    assertThat(notBeforeToken.getAudiences()).isNull();
    assertThat(notBeforeToken.getJwtId()).isNull();
    assertThat(notBeforeToken.getExpiration()).isNull();
    assertThat(notBeforeToken.getIssuedAt()).isNull();
    assertThat(notBeforeToken.getClaim("blah")).isNull();

    assertThrows(IllegalStateException.class, notBeforeToken::getAlgorithm);
    assertThat(notBeforeToken.getType()).isNull();
    assertThat(notBeforeToken.getContentType()).isNull();
    assertThat(notBeforeToken.getKeyId()).isNull();
  }

  @Test
  public void notBeforeToken_clockSkew_success() throws Exception {
    JSONObject payload = new JSONObject();
    // Set the not before time to 1 minutes in the future.
    Instant instant = Instant.now().plus(Duration.ofMinutes(1));
    payload.put(JwtNames.CLAIM_NOT_BEFORE, instant.getEpochSecond());
    // Set the clock skew to 2 minutes.
    Jwt notBeforeToken =
        new Jwt(new JSONObject(), payload, Clock.systemUTC(), Duration.ofMinutes(2));

    assertThat(notBeforeToken.getNotBefore().getEpochSecond()).isEqualTo(instant.getEpochSecond());

    assertThat(notBeforeToken.getIssuer()).isNull();
    assertThat(notBeforeToken.getSubject()).isNull();
    assertThat(notBeforeToken.getAudiences()).isNull();
    assertThat(notBeforeToken.getJwtId()).isNull();
    assertThat(notBeforeToken.getExpiration()).isNull();
    assertThat(notBeforeToken.getIssuedAt()).isNull();
    assertThat(notBeforeToken.getClaim("blah")).isNull();

    assertThrows(IllegalStateException.class, notBeforeToken::getAlgorithm);
    assertThat(notBeforeToken.getType()).isNull();
    assertThat(notBeforeToken.getContentType()).isNull();
    assertThat(notBeforeToken.getKeyId()).isNull();
  }
}
