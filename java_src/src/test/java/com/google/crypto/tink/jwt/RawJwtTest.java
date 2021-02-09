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

import java.time.Instant;
import java.util.Set;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(juerg): Add validation and tests for StringOrURI.

/** Unit tests for RawJwt */
@RunWith(JUnit4.class)
public final class RawJwtTest {

  @Test
  public void emptyToken_getRegisteredClaimShouldThrow() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    assertThrows(JwtInvalidException.class, token::getIssuer);
    assertThrows(JwtInvalidException.class, token::getAudiences);
    assertThrows(JwtInvalidException.class, token::getSubject);
    assertThrows(JwtInvalidException.class, token::getJwtId);
    assertThrows(JwtInvalidException.class, token::getExpiration);
    assertThrows(JwtInvalidException.class, token::getNotBefore);
    assertThrows(JwtInvalidException.class, token::getIssuedAt);
  }

  @Test
  public void emptyToken_hasShouldReturnFalse() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    assertThat(token.hasIssuer()).isFalse();
    assertThat(token.hasSubject()).isFalse();
    assertThat(token.hasAudiences()).isFalse();
    assertThat(token.hasJwtId()).isFalse();
    assertThat(token.hasExpiration()).isFalse();
    assertThat(token.hasNotBefore()).isFalse();
    assertThat(token.hasIssuedAt()).isFalse();
  }

  @Test
  public void setIssuer_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setIssuer("foo").build();
    assertThat(token.hasIssuer()).isTrue();
    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void addAudience_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addAudience("foo").build();
    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void addMulitpleAudiences_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addAudience("foo").addAudience("bar").build();
    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void setUnsetSubject_shouldThrow() throws Exception {
    // TODO(juerg): Don't allow null values to be set.
    RawJwt token = new RawJwt.Builder().setSubject("foo").setSubject(null).build();
    assertThat(token.hasSubject()).isFalse();
    assertThrows(JwtInvalidException.class, token::getSubject);
  }

  @Test
  public void setSubject_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setSubject("foo").build();
    assertThat(token.hasSubject()).isTrue();
    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void setJwtId_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setJwtId("foo").build();
    assertThat(token.hasJwtId()).isTrue();
    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void addStringClaim_issuer_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addStringClaim(JwtNames.CLAIM_ISSUER, "blah"));
  }

  @Test
  public void addStringClaim_subject_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addStringClaim(JwtNames.CLAIM_SUBJECT, "blah"));
  }

  @Test
  public void addEncodedJsonArrayClaim_audience_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addJsonArrayClaim(JwtNames.CLAIM_AUDIENCE, "[\"a\", \"b\"]"));
  }

  @Test
  public void addStringClaim_jwtId_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addStringClaim(JwtNames.CLAIM_JWT_ID, "blah"));
  }

  @Test
  public void addNumberClaim_expiration_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addNumberClaim(JwtNames.CLAIM_EXPIRATION, 1234567));
  }

  @Test
  public void addNumberClaim_issuedAt_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addNumberClaim(JwtNames.CLAIM_ISSUED_AT, 1234567));
  }

  @Test
  public void addNumberClaim_notBefore_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addNumberClaim(JwtNames.CLAIM_NOT_BEFORE, 1234567));
  }

  @Test
  public void addAndGetStringClaim_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addStringClaim("claim", "value").build();

    assertThat(token.getStringClaim("claim")).isEqualTo("value");
  }

  @Test
  public void addAndGetIntegerAsNumberClaim_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addNumberClaim("claim", 1).build();

    // A Json Number is always a floating point.
    assertThat(token.getNumberClaim("claim")).isEqualTo(1.0);
  }

  @Test
  public void addAndGetDoubleAsNumberClaim_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addNumberClaim("claim", 123.4).build();

    assertThat(token.getNumberClaim("claim")).isEqualTo(123.4);
  }

  @Test
  public void addAndGetBooleanClaim_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addBooleanClaim("claim", true).build();

    assertThat(token.getBooleanClaim("claim")).isTrue();
  }

  @Test
  public void addAndCheckNullClaim_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addNullClaim("claim").build();

    assertThat(token.isNullClaim("claim")).isTrue();
  }

  @Test
  public void hasUnknownClaim_false() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    assertThat(token.hasClaim("claim")).isFalse();
  }

  @Test
  public void getUnknownClaim_shouldThrow() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThrows(JwtInvalidException.class, () -> token.getBooleanClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getNumberClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getStringClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getJsonArrayClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getJsonObjectClaim("claim"));
  }

  @Test
  public void unknownClaimIsNotNull() throws Exception {
    RawJwt token = new RawJwt.Builder().build();
    assertThat(token.isNullClaim("claim")).isFalse();
  }

  @Test
  public void addAndGetEncodedJsonArrayClaim_success() throws Exception {
    String encodedJsonArray = "[true, 123, 123.456, \"value\", [1, 2]]";
    RawJwt token =
        new RawJwt.Builder().addJsonArrayClaim("collection", encodedJsonArray).build();

    assertThat(token.hasClaim("collection")).isTrue();
    String output = token.getJsonArrayClaim("collection");
    assertThat(output).isEqualTo("[true,123,123.456,\"value\",[1,2]]");
  }

  @Test
  public void addInvalidEncodedJsonArrayClaim_shouldThrow() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonArrayClaim("array", "\"foo\""));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonArrayClaim("array", "123"));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonArrayClaim("array", "\"[123]\""));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonArrayClaim("array", "null"));
  }

  @Test
  public void addAndGetEncodedJsonObjectClaim_success() throws Exception {
    String encodedJsonObject = "{\"boolean\":false,\"obj1\":{\"obj2\":{\"42\":42}}}";
    RawJwt token =
        new RawJwt.Builder().addJsonObjectClaim("obj", encodedJsonObject).build();

    assertThat(token.hasClaim("obj")).isTrue();
    String output = token.getJsonObjectClaim("obj");

    JSONObject obj = new JSONObject(output);
    assertThat(obj.getBoolean("boolean")).isFalse();
    assertThat(obj.getJSONObject("obj1").getJSONObject("obj2").getInt("42")).isEqualTo(42);
  }

  @Test
  public void addInvalidEncodedJsonObjectClaim_shouldThrow() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonObjectClaim("obj", "\"foo\""));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonObjectClaim("obj", "123"));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonObjectClaim("obj", "\"{\"a\":1}\""));
    assertThrows(
        JwtInvalidException.class,
        () -> new RawJwt.Builder().addJsonObjectClaim("obj", "null"));
  }

  @Test
  public void setExpiration_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setExpiration(instant).build();

    assertThat(token.hasExpiration()).isTrue();
    assertThat(token.getExpiration()).isEqualTo(instant.truncatedTo(SECONDS));
  }

  @Test
  public void setNotBefore_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setNotBefore(instant).build();

    assertThat(token.hasNotBefore()).isTrue();
    assertThat(token.getNotBefore()).isEqualTo(instant.truncatedTo(SECONDS));
  }


  @Test
  public void setIssuedAt_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setIssuedAt(instant).build();

    assertThat(token.hasIssuedAt()).isTrue();
    assertThat(token.getIssuedAt()).isEqualTo(instant.truncatedTo(SECONDS));
  }

  @Test
  public void getJsonPayload_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setJwtId("blah").build();
    assertThat(token.getJsonPayload()).isEqualTo("{\"jti\":\"blah\"}");
  }

  @Test
  public void fromJsonPayload_success() throws Exception {
    String input =
        "{\"jti\": \"abc123\", \"aud\": [\"me\", \"you\"], \"iat\": 123, "
            + "\"custom\": {\"int\": 123, \"string\": \"value\"}}";

    RawJwt token = RawJwt.fromJsonPayload(input);
    assertThat(token.getJwtId()).isEqualTo("abc123");
    assertThat(token.getAudiences()).containsExactly("me", "you");
    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(123));

    String encodedObject = token.getJsonObjectClaim("custom");
    JSONObject custom = new JSONObject(encodedObject);
    assertThat(custom.getInt("int")).isEqualTo(123);
    assertThat(custom.getString("string")).isEqualTo("value");
  }

  @Test
  public void fromJsonPayloadWithFloatIssuedAt_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload("{\"iat\": 123.456}");
    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(123));
  }

  @Test
  public void fromEmptyJsonPayload_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload("{}");
    assertThat(token.hasIssuer()).isFalse();
  }

  @Test
  public void fromInvalidJsonPayload_shouldThrow() throws Exception {
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("invalid!!!"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"iss\": true}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"iss\": null}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"sub\": 123}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"aud\": 123}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"aud\": [\"a\", 1]}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"aud\": [null]}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"jti\": []}"));
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload("{\"exp\": \"123\"}"));
  }

  @Test
  public void fromJsonPayloadWithAudienceAsString_convertedToArray() throws Exception {
    // According to https://tools.ietf.org/html/rfc7519#section-4.1.3, this should be accepted.
    String input = "{\"aud\": \"me\"}";
    RawJwt token = RawJwt.fromJsonPayload(input);
    assertThat(token.getAudiences()).containsExactly("me");
    assertThat(token.getJsonPayload()).isEqualTo("{\"aud\":[\"me\"]}");
  }

  @Test
  public void fromJsonPayloadWithEmptyAudience_shouldThrow() throws Exception {
    String input = "{\"jti\": \"id\", \"aud\": []}";
    // An audience claim that is present but empty results in a token that must always be rejected
    // by the receiver, because the receiver is required to test that it is among the audiences.
    // See https://tools.ietf.org/html/rfc7519#section-4.1.3. It is better to consider it invalid.
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(input));
  }

  @Test
  public void getClaimsOfDifferentType_shouldThrow() throws Exception {
    RawJwt token =
        new RawJwt.Builder()
            .addNumberClaim("number", 1)
            .addStringClaim("string", "value")
            .addBooleanClaim("boolean", true)
            .addStringClaim("booleanString", "true")
            .addStringClaim("numberString", "1")
            .addNullClaim("nullClaim")
            .build();
    assertThrows(JwtInvalidException.class, () -> token.getBooleanClaim("number"));
    assertThrows(JwtInvalidException.class, () -> token.getBooleanClaim("booleanString"));
    assertThrows(JwtInvalidException.class, () -> token.getNumberClaim("string"));
    assertThrows(JwtInvalidException.class, () -> token.getNumberClaim("numberString"));
    assertThrows(JwtInvalidException.class, () -> token.getStringClaim("number"));
    assertThrows(JwtInvalidException.class, () -> token.getStringClaim("boolean"));
    assertThrows(JwtInvalidException.class, () -> token.getBooleanClaim("nullClaim"));
    assertThrows(JwtInvalidException.class, () -> token.getNumberClaim("nullClaim"));
    assertThrows(JwtInvalidException.class, () -> token.getStringClaim("nullClaim"));
  }

  @Test
  public void hasNullClaimOfDifferentType_returnsFalse() throws Exception {
    RawJwt token = new RawJwt.Builder().addBooleanClaim("boolean", true).build();
    assertThat(token.isNullClaim("boolean")).isFalse();
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

    Set<String> claimSet = token.customClaimNames();
    assertThat(claimSet).containsExactly("string", "boolean", "number", "nothing");
  }

  @Test
  public void changingValueInBuilderDoesntChangeAlreadyBuiltToken() throws Exception {
    RawJwt.Builder builder = new RawJwt.Builder();

    builder.setSubject("foo");
    RawJwt fooToken = builder.build();

    builder.setSubject("bar");
    RawJwt barToken = builder.build();

    assertThat(fooToken.getSubject()).isEqualTo("foo");
    assertThat(barToken.getSubject()).isEqualTo("bar");
  }
}
