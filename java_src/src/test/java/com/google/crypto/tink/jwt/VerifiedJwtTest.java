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

import java.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(juerg): Add validation and tests for StringOrURI.

/** Unit tests for VerifiedJwt */
@RunWith(JUnit4.class)
public final class VerifiedJwtTest {
  @Test
  public void emptyJwt_success() throws Exception {
    VerifiedJwt emptyToken = new VerifiedJwt(new RawJwt.Builder().build());

    assertThrows(JwtInvalidException.class, emptyToken::getIssuer);
    assertThrows(JwtInvalidException.class, emptyToken::getSubject);
    assertThrows(JwtInvalidException.class, emptyToken::getAudiences);
    assertThrows(JwtInvalidException.class, emptyToken::getJwtId);
    assertThrows(JwtInvalidException.class, emptyToken::getExpiration);
    assertThrows(JwtInvalidException.class, emptyToken::getNotBefore);
    assertThrows(JwtInvalidException.class, emptyToken::getIssuedAt);
  }

  @Test
  public void getIssuer_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setIssuer("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void getSubject_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setSubject("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void getAudiences_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().addAudience("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void getMultipleAudiences_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().addAudience("foo").addAudience("bar").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void getJwtId_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setJwtId("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void getJwtIdFromInt_throwsException() throws Exception {
    RawJwt rawToken = new RawJwt.Builder("{\"jti\":1234}").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    // TODO(juerg): Throw a JwtInvalidException on construction of RawJwt.
    assertThrows(JwtInvalidException.class, token::getJwtId);
  }

  @Test
  public void getJwtIdFromNull_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder("{\"jti\":null}").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    assertThrows(JwtInvalidException.class, token::getJwtId);
  }

  @Test
  public void getExpiration_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setExpiration(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getNotBefore_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setNotBefore(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getNotBefore()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getIssuedAt_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setIssuedAt(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

 @Test
  public void getRegisteredClaim_shouldThrow() throws Exception {
    RawJwt rawToken =
        new RawJwt.Builder()
            .setExpiration(Instant.ofEpochSecond(1234567))
            .setIssuer("issuer")
            .setSubject("subject")
            .addAudience("audience")
            .setIssuedAt(Instant.ofEpochSecond(2345678))
            .setNotBefore(Instant.ofEpochSecond(3456789))
            .setJwtId("id")
            .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThrows(
        IllegalArgumentException.class, () -> token.getNumberClaim(JwtNames.CLAIM_EXPIRATION));
    assertThrows(IllegalArgumentException.class, () -> token.getStringClaim(JwtNames.CLAIM_ISSUER));
    assertThrows(
        IllegalArgumentException.class, () -> token.getStringClaim(JwtNames.CLAIM_SUBJECT));
    assertThrows(
        IllegalArgumentException.class, () -> token.getJsonArrayClaim(JwtNames.CLAIM_AUDIENCE));
    assertThrows(
        IllegalArgumentException.class, () -> token.getNumberClaim(JwtNames.CLAIM_ISSUED_AT));
    assertThrows(IllegalArgumentException.class, () -> token.getStringClaim(JwtNames.CLAIM_JWT_ID));
    assertThrows(
        IllegalArgumentException.class, () -> token.getNumberClaim(JwtNames.CLAIM_NOT_BEFORE));
  }

  @Test
  public void getNotRegisteredSimpleClaims_success() throws Exception {
    RawJwt rawToken =
        new RawJwt.Builder()
            .addStringClaim("string", "issuer")
            .addNumberClaim("int", 123)
            .addBooleanClaim("bool", true)
            .addNumberClaim("double", 123.456)
            .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.getBooleanClaim("bool")).isTrue();
    assertThat(token.getStringClaim("string")).isEqualTo("issuer");
    assertThat(token.getNumberClaim("int")).isEqualTo(123.0);
    assertThat(token.getNumberClaim("double")).isEqualTo(123.456);
  }

  @Test
  public void getNullClaim_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder()
        .addNullClaim("null_object")
        .addStringClaim("null_string", "null")
        .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    assertThat(token.isNullClaim("null_object")).isTrue();
    assertThat(token.isNullClaim("null_string")).isFalse();
    assertThat(token.isNullClaim("unknown_claim")).isFalse();
  }

  @Test
  public void getNotRegisteredJsonArrayClaim_success() throws Exception {
    RawJwt rawToken =
        new RawJwt.Builder()
            .setJwtId("id")
            .addJsonArrayClaim("collection", "[true, 123, 123.456, \"value\", [1,2]]")
            .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    assertThat(token.getJsonArrayClaim("collection"))
        .isEqualTo("[true,123,123.456,\"value\",[1,2]]");
  }

  @Test
  public void getNotRegisteredJsonObjectClaim_success() throws Exception {
    RawJwt rawToken =
        new RawJwt.Builder()
            .setJwtId("id")
            .addJsonObjectClaim("obj", "{\"obj1\": {\"obj2\": {\"42\": [42]}}}")
            .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    assertThat(token.getJwtId()).isEqualTo("id");
    assertThat(token.getJsonObjectClaim("obj"))
        .isEqualTo("{\"obj1\":{\"obj2\":{\"42\":[42]}}}");
  }
}
