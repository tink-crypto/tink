// Copyright 2021 Google LLC
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
  public void emptyToken_getMethodsShouldThrow() throws Exception {
    VerifiedJwt emptyToken = new VerifiedJwt(new RawJwt.Builder().build());

    assertThrows(JwtInvalidException.class, emptyToken::getIssuer);
    assertThrows(JwtInvalidException.class, emptyToken::getSubject);
    assertThrows(JwtInvalidException.class, emptyToken::getAudiences);
    assertThrows(JwtInvalidException.class, emptyToken::getJwtId);
    assertThrows(JwtInvalidException.class, emptyToken::getExpiration);
    assertThrows(JwtInvalidException.class, emptyToken::getNotBefore);
    assertThrows(JwtInvalidException.class, emptyToken::getIssuedAt);
    assertThrows(JwtInvalidException.class, () -> emptyToken.getBooleanClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> emptyToken.getStringClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> emptyToken.getNumberClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> emptyToken.getJsonArrayClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> emptyToken.getJsonObjectClaim("claim"));
  }

  @Test
  public void emptyToken_hasMethodsShouldReturnFalse() throws Exception {
    RawJwt emptyToken = new RawJwt.Builder().build();
    assertThat(emptyToken.hasIssuer()).isFalse();
    assertThat(emptyToken.hasSubject()).isFalse();
    assertThat(emptyToken.hasAudiences()).isFalse();
    assertThat(emptyToken.hasJwtId()).isFalse();
    assertThat(emptyToken.hasExpiration()).isFalse();
    assertThat(emptyToken.hasNotBefore()).isFalse();
    assertThat(emptyToken.hasIssuedAt()).isFalse();
    assertThat(emptyToken.hasBooleanClaim("claim")).isFalse();
    assertThat(emptyToken.hasNumberClaim("claim")).isFalse();
    assertThat(emptyToken.hasStringClaim("claim")).isFalse();
    assertThat(emptyToken.hasJsonArrayClaim("claim")).isFalse();
    assertThat(emptyToken.hasJsonObjectClaim("claim")).isFalse();
  }

  @Test
  public void emptyToken_isNullClaimReturnFalse() throws Exception {
    RawJwt emptyToken = new RawJwt.Builder().build();
    assertThat(emptyToken.isNullClaim("claim")).isFalse();
  }

  @Test
  public void getIssuer_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setIssuer("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasIssuer()).isTrue();
    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void getSubject_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setSubject("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasSubject()).isTrue();
    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void getAudiences_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().addAudience("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void getMultipleAudiences_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().addAudience("foo").addAudience("bar").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void getJwtId_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setJwtId("foo").build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasJwtId()).isTrue();
    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void getExpiration_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setExpiration(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasExpiration()).isTrue();
    assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getNotBefore_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setNotBefore(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasNotBefore()).isTrue();
    assertThat(token.getNotBefore()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getIssuedAt_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder().setIssuedAt(Instant.ofEpochSecond(1234567)).build();
    VerifiedJwt token = new VerifiedJwt(rawToken);

    assertThat(token.hasIssuedAt()).isTrue();
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

    assertThat(token.hasBooleanClaim("bool")).isTrue();
    assertThat(token.getBooleanClaim("bool")).isTrue();
    assertThat(token.hasStringClaim("string")).isTrue();
    assertThat(token.getStringClaim("string")).isEqualTo("issuer");
    assertThat(token.hasNumberClaim("int")).isTrue();
    assertThat(token.getNumberClaim("int")).isEqualTo(123.0);
    assertThat(token.hasNumberClaim("double")).isTrue();
    assertThat(token.getNumberClaim("double")).isEqualTo(123.456);
  }

  @Test
  public void getNullClaim_success() throws Exception {
    RawJwt rawToken = new RawJwt.Builder()
        .addNullClaim("null_object")
        .addStringClaim("null_string", "null")
        .build();
    VerifiedJwt token = new VerifiedJwt(rawToken);
    assertThat(token.hasStringClaim("null_object")).isFalse();
    assertThat(token.isNullClaim("null_object")).isTrue();
    assertThat(token.hasStringClaim("null_string")).isTrue();
    assertThat(token.isNullClaim("null_string")).isFalse();
    assertThat(token.hasStringClaim("unknown_claim")).isFalse();
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
    assertThat(token.hasJsonArrayClaim("collection")).isTrue();
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
    assertThat(token.hasJsonObjectClaim("obj")).isTrue();
    assertThat(token.getJsonObjectClaim("obj"))
        .isEqualTo("{\"obj1\":{\"obj2\":{\"42\":[42]}}}");
  }

  @Test
  public void customClaimNames_success() throws Exception {
    RawJwt token =
        new RawJwt.Builder()
            .setIssuer("issuer")
            .setExpiration(Instant.ofEpochSecond(1234567))
            .addStringClaim("string", "value")
            .addBooleanClaim("boolean", true)
            .addNumberClaim("number", 123.456)
            .addNullClaim("nothing")
            .build();
    assertThat(token.customClaimNames()).containsExactly("string", "boolean", "number", "nothing");
  }

  @Test
  public void customClaimNames_empty() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    assertThat(token.customClaimNames()).isEmpty();
  }
}
