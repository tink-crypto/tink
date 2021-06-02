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
import static org.junit.Assert.assertThrows;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(juerg): Add validation and tests for StringOrURI.

/** Unit tests for RawJwt */
@RunWith(JUnit4.class)
public final class RawJwtTest {

  @Test
  public void emptyToken_getRegisteredClaimShouldThrow() throws Exception {
    RawJwt token = RawJwt.newBuilder().withoutExpiration().build();
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
    RawJwt token = RawJwt.newBuilder().withoutExpiration().build();
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
    RawJwt token = RawJwt.newBuilder().setIssuer("foo").withoutExpiration().build();
    assertThat(token.hasIssuer()).isTrue();
    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void addAudience_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addAudience("foo").withoutExpiration().build();
    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void addMulitpleAudiences_success() throws Exception {
    RawJwt token =
        RawJwt.newBuilder().addAudience("foo").addAudience("bar").withoutExpiration().build();
    assertThat(token.hasAudiences()).isTrue();
    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void setNullNameOrValue_shouldThrow() throws Exception {
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setIssuer(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setSubject(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().addAudience(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setJwtId(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setExpiration(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setNotBefore(null));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().setIssuedAt(null));
    assertThrows(
        NullPointerException.class, () -> RawJwt.newBuilder().addBooleanClaim(null, true));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().addNumberClaim(null, 1.0));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().addStringClaim(null, "a"));
    assertThrows(NullPointerException.class, () -> RawJwt.newBuilder().addStringClaim("a", null));
    assertThrows(
        NullPointerException.class,
        () -> RawJwt.newBuilder().addJsonObjectClaim(null, "{\"a\":\"b\"}"));
    assertThrows(
        NullPointerException.class, () -> RawJwt.newBuilder().addJsonObjectClaim("a", null));
    assertThrows(
        NullPointerException.class, () -> RawJwt.newBuilder().addJsonArrayClaim(null, "[1, 2]"));
    assertThrows(
        NullPointerException.class, () -> RawJwt.newBuilder().addJsonArrayClaim("a", null));
  }

  @Test
  public void setInvalidStrings_fails() throws Exception {
    RawJwt.Builder token = RawJwt.newBuilder();
    assertThrows(IllegalArgumentException.class, () -> token.setIssuer("\uD834"));
    assertThrows(IllegalArgumentException.class, () -> token.setSubject("\uD834"));
    assertThrows(IllegalArgumentException.class, () -> token.addAudience("\uD834"));
    assertThrows(IllegalArgumentException.class, () -> token.setJwtId("\uD834"));
    assertThrows(IllegalArgumentException.class, () -> token.addStringClaim("claim", "\uD834"));
    assertThrows(JwtInvalidException.class, () -> token.addJsonArrayClaim("claim", "[\"\uD834\"]"));
    assertThrows(
        JwtInvalidException.class, () -> token.addJsonObjectClaim("claim", "{\"a\":\"\uD834\"}"));
    assertThrows(
        JwtInvalidException.class, () -> token.addJsonObjectClaim("claim", "{\"\uD834\":\"a\"}"));
  }

  @Test
  public void setSubject_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().setSubject("foo").withoutExpiration().build();
    assertThat(token.hasSubject()).isTrue();
    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void setJwtId_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().setJwtId("foo").withoutExpiration().build();
    assertThat(token.hasJwtId()).isTrue();
    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void addStringClaim_issuer_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addStringClaim(JwtNames.CLAIM_ISSUER, "blah"));
  }

  @Test
  public void addStringClaim_subject_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addStringClaim(JwtNames.CLAIM_SUBJECT, "blah"));
  }

  @Test
  public void addEncodedJsonArrayClaim_audience_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addJsonArrayClaim(JwtNames.CLAIM_AUDIENCE, "[\"a\", \"b\"]"));
  }

  @Test
  public void addStringClaim_jwtId_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addStringClaim(JwtNames.CLAIM_JWT_ID, "blah"));
  }

  @Test
  public void addNumberClaim_expiration_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addNumberClaim(JwtNames.CLAIM_EXPIRATION, 1234567));
  }

  @Test
  public void addNumberClaim_issuedAt_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addNumberClaim(JwtNames.CLAIM_ISSUED_AT, 1234567));
  }

  @Test
  public void addNumberClaim_notBefore_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().addNumberClaim(JwtNames.CLAIM_NOT_BEFORE, 1234567));
  }

  @Test
  public void addAndGetStringClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addStringClaim("claim", "value").withoutExpiration().build();

    assertThat(token.hasStringClaim("claim")).isTrue();
    assertThat(token.getStringClaim("claim")).isEqualTo("value");
  }

  @Test
  public void addAndGetIntegerAsNumberClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addNumberClaim("claim", 1).withoutExpiration().build();

    // A Json Number is always a floating point.
    assertThat(token.hasNumberClaim("claim")).isTrue();
    assertThat(token.getNumberClaim("claim")).isEqualTo(1.0);
  }

  @Test
  public void addAndGetDoubleAsNumberClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addNumberClaim("claim", 123.4).withoutExpiration().build();

    assertThat(token.hasNumberClaim("claim")).isTrue();
    assertThat(token.getNumberClaim("claim")).isEqualTo(123.4);
  }

  @Test
  public void addAndGetBooleanClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addBooleanClaim("claim", true).withoutExpiration().build();

    assertThat(token.hasBooleanClaim("claim")).isTrue();
    assertThat(token.getBooleanClaim("claim")).isTrue();
  }

  @Test
  public void addAndCheckNullClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addNullClaim("claim").withoutExpiration().build();

    assertThat(token.isNullClaim("claim")).isTrue();
  }

  @Test
  public void hasUnknownClaim_false() throws Exception {
    RawJwt token = RawJwt.newBuilder().withoutExpiration().build();
    assertThat(token.hasBooleanClaim("claim")).isFalse();
    assertThat(token.hasNumberClaim("claim")).isFalse();
    assertThat(token.hasStringClaim("claim")).isFalse();
    assertThat(token.hasJsonArrayClaim("claim")).isFalse();
    assertThat(token.hasJsonObjectClaim("claim")).isFalse();
  }

  @Test
  public void getUnknownClaim_shouldThrow() throws Exception {
    RawJwt token = RawJwt.newBuilder().withoutExpiration().build();

    assertThrows(JwtInvalidException.class, () -> token.getBooleanClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getNumberClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getStringClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getJsonArrayClaim("claim"));
    assertThrows(JwtInvalidException.class, () -> token.getJsonObjectClaim("claim"));
  }

  @Test
  public void unknownClaimIsNotNull() throws Exception {
    RawJwt token = RawJwt.newBuilder().withoutExpiration().build();
    assertThat(token.isNullClaim("claim")).isFalse();
  }

  @Test
  public void addAndGetEncodedJsonArrayClaim_success() throws Exception {
    String encodedJsonArray = "[true, 123, 123.456, \"value\", [1, 2]]";
    RawJwt token =
        RawJwt.newBuilder()
            .addJsonArrayClaim("collection", encodedJsonArray)
            .withoutExpiration()
            .build();

    assertThat(token.hasJsonArrayClaim("collection")).isTrue();
    String output = token.getJsonArrayClaim("collection");
    assertThat(output).isEqualTo("[true,123,123.456,\"value\",[1,2]]");
  }

  @Test
  public void addInvalidEncodedJsonArrayClaim_shouldThrow() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonArrayClaim("array", "\"foo\""));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonArrayClaim("array", "123"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonArrayClaim("array", "\"[123]\""));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonArrayClaim("array", "null"));
  }

  @Test
  public void addAndGetEncodedJsonObjectClaim_success() throws Exception {
    String encodedJsonObject = "{\"boolean\":false,\"obj1\":{\"obj2\":{\"42\":42}}}";
    RawJwt token =
        RawJwt.newBuilder()
            .addJsonObjectClaim("obj", encodedJsonObject)
            .withoutExpiration()
            .build();

    assertThat(token.hasJsonObjectClaim("obj")).isTrue();
    String output = token.getJsonObjectClaim("obj");

    JsonObject obj = JsonParser.parseString(output).getAsJsonObject();
    assertThat(obj.get("boolean").getAsBoolean()).isFalse();
    assertThat(obj.getAsJsonObject("obj1").getAsJsonObject("obj2").get("42").getAsInt())
        .isEqualTo(42);
  }

  @Test
  public void addInvalidEncodedJsonObjectClaim_shouldThrow() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonObjectClaim("obj", "\"foo\""));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonObjectClaim("obj", "123"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonObjectClaim("obj", "\"{\"a\":1}\""));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.newBuilder().addJsonObjectClaim("obj", "null"));
  }

  @Test
  public void setExpiration_success() throws Exception {
    Instant instant = Instant.ofEpochMilli(1234567890);
    RawJwt token = RawJwt.newBuilder().setExpiration(instant).build();

    assertThat(token.hasExpiration()).isTrue();
    assertThat(token.getExpiration()).isEqualTo(instant);
  }

  @Test
  public void setExpiration_withoutExpiration_fail() throws Exception {
    Instant instant = Instant.ofEpochMilli(1234567890);
    assertThrows(
        IllegalArgumentException.class,
        () -> RawJwt.newBuilder().setExpiration(instant).withoutExpiration().build());
  }

  @Test
  public void neither_setExpiration_nor_withoutExpiration_fail() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().build());
  }

  @Test
  public void setNotBefore_success() throws Exception {
    Instant instant = Instant.ofEpochMilli(1234567890);
    RawJwt token = RawJwt.newBuilder().setNotBefore(instant).withoutExpiration().build();

    assertThat(token.hasNotBefore()).isTrue();
    assertThat(token.getNotBefore()).isEqualTo(instant);
  }


  @Test
  public void setIssuedAt_success() throws Exception {
    Instant instant = Instant.ofEpochMilli(1234567890);
    RawJwt token = RawJwt.newBuilder().setIssuedAt(instant).withoutExpiration().build();

    assertThat(token.hasIssuedAt()).isTrue();
    assertThat(token.getIssuedAt()).isEqualTo(instant);
  }

  @Test
  public void largeTimestamp_success() throws Exception {
    Instant instant = Instant.ofEpochMilli(253402300799000L);
    RawJwt token = RawJwt.newBuilder()
        .setExpiration(instant).setIssuedAt(instant).setNotBefore(instant).build();

    assertThat(token.hasExpiration()).isTrue();
    assertThat(token.getExpiration()).isEqualTo(instant);
    assertThat(token.hasIssuedAt()).isTrue();
    assertThat(token.getIssuedAt()).isEqualTo(instant);
    assertThat(token.hasNotBefore()).isTrue();
    assertThat(token.getNotBefore()).isEqualTo(instant);
  }

  @Test
  public void tooLargeTimestamp_throws() throws Exception {
    Instant instant = Instant.ofEpochMilli(253402300800000L);
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setExpiration(instant));
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setIssuedAt(instant));
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setNotBefore(instant));
  }

  @Test
  public void negativeTimestamp_throws() throws Exception {
    Instant instant = Instant.ofEpochMilli(-1);
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setExpiration(instant));
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setIssuedAt(instant));
    assertThrows(IllegalArgumentException.class, () -> RawJwt.newBuilder().setNotBefore(instant));
  }

  @Test
  public void getJsonPayload_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().setJwtId("blah").withoutExpiration().build();
    assertThat(token.getJsonPayload()).isEqualTo("{\"jti\":\"blah\"}");
  }

  @Test
  public void getJsonPayloadWithNullClaim_success() throws Exception {
    RawJwt token = RawJwt.newBuilder().addNullClaim("null_claim").withoutExpiration().build();
    assertThat(token.getJsonPayload()).isEqualTo("{\"null_claim\":null}");
  }

  @Test
  public void fromJsonPayload_success() throws Exception {
    String input =
        "{\"jti\": \"abc123\", \"aud\": [\"me\", \"you\"], \"iat\": 123, "
            + "\"custom\": {\"int\": 123, \"string\": \"value\"}}";

    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), input);
    assertThat(token.getJwtId()).isEqualTo("abc123");
    assertThat(token.getAudiences()).containsExactly("me", "you");
    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(123));

    String encodedObject = token.getJsonObjectClaim("custom");
    JsonObject custom = JsonParser.parseString(encodedObject).getAsJsonObject();
    assertThat(custom.get("int").getAsInt()).isEqualTo(123);
    assertThat(custom.get("string").getAsString()).isEqualTo("value");
  }

  @Test
  public void fromJsonPayloadWithTypeHeader_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.of("myType"), "{}");
    assertThat(token.getTypeHeader()).isEqualTo("myType");
  }

  @Test
  public void fromJsonPayloadWithFloatIssuedAt_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), "{\"iat\": 123.456}");
    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochMilli(123456));
  }

  @Test
  public void fromJsonPayloadWithExpFloatIssuedAt_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), "{\"iat\":1e10}");
    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochMilli(10000000000000L));
  }

  @Test
  public void fromJsonPayloadWithTooLargeIssuedAt_throws() throws Exception {
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(
        Optional.empty(), "{\"iat\":1e30}"));
  }

  @Test
  public void fromJsonPayloadWithInfinityIssuedAt_throws() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"iat\":Infinity}"));
  }

  @Test
  public void fromEmptyJsonPayload_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), "{}");
    assertThat(token.hasTypeHeader()).isFalse();
    assertThat(token.hasIssuer()).isFalse();
  }

  @Test
  public void fromJsonPayloadWithNullClaim_success() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), "{\"null_claim\":null}");
    assertThat(token.isNullClaim("null_claim")).isTrue();
  }

  @Test
  public void fromNullJsonPayload_shouldThrow() throws Exception {
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), "null"));
  }

  @Test
  public void fromInvalidJsonPayload_shouldThrow() throws Exception {
    assertThrows(
        JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), "invalid!!!"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"iss\": true}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"iss\": null}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"sub\": 123}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"aud\": 123}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"aud\": [\"a\", 1]}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"aud\": [null]}"));
    assertThrows(
        JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"jti\": []}"));
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"exp\": \"123\"}"));
  }

  @Test
  public void fromJsonPayloadWithValidJsonEscapedCharacter_shouldThrow() throws Exception {
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), "{\"iss\":\"\\uD834\\uDD1E\"}");
    assertThat(token.hasIssuer()).isTrue();
    assertThat(token.getIssuer()).isEqualTo("\uD834\uDD1E");
  }

  @Test
  public void fromJsonPayloadWithInvalidJsonEscapedCharacter_shouldThrow() throws Exception {
    // the json string contains "\uD834", which gets decoded by the json decoder
    // into an invalid UTF16 character.
    assertThrows(
        JwtInvalidException.class,
        () -> RawJwt.fromJsonPayload(Optional.empty(), "{\"iss\":\"\\uD834\"}"));
  }

  @Test
  public void fromJsonPayloadWithAudienceAsString_convertedToArray() throws Exception {
    // According to https://tools.ietf.org/html/rfc7519#section-4.1.3, this should be accepted.
    String input = "{\"aud\": \"me\"}";
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), input);
    assertThat(token.getAudiences()).containsExactly("me");
    assertThat(token.getJsonPayload()).isEqualTo("{\"aud\":[\"me\"]}");
  }

  @Test
  public void fromJsonPayloadWithEmptyAudience_shouldThrow() throws Exception {
    String input = "{\"jti\": \"id\", \"aud\": []}";
    // An audience claim that is present but empty results in a token that must always be rejected
    // by the receiver, because the receiver is required to test that it is among the audiences.
    // See https://tools.ietf.org/html/rfc7519#section-4.1.3. It is better to consider it invalid.
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), input));
  }

  @Test
  public void fromJsonPayloadWithComments_shouldThrow () throws Exception {
    String input = "{\"sub\": \"subject\" /*, \"iss\": \"issuer\" */}";
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), input));
  }

  @Test
  public void fromJsonPayloadWithEscapedChars_success() throws Exception {
    String input = "{\"i\\u0073\\u0073\": \"\\u0061lice\"}";
    RawJwt token = RawJwt.fromJsonPayload(Optional.empty(), input);
    assertThat(token.getIssuer()).isEqualTo("alice");
  }

  @Test
  public void fromJsonPayloadWithoutQuotes_shoudThrow() throws Exception {
    String input = "{iss: issuer}";
    assertThrows(JwtInvalidException.class, () -> RawJwt.fromJsonPayload(Optional.empty(), input));
  }


  @Test
  public void getClaimsOfDifferentType_shouldThrow() throws Exception {
    RawJwt token =
        RawJwt.newBuilder()
            .addNumberClaim("number", 1)
            .addStringClaim("string", "value")
            .addBooleanClaim("boolean", true)
            .addStringClaim("booleanString", "true")
            .addStringClaim("numberString", "1")
            .addNullClaim("nullClaim")
            .withoutExpiration()
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
    RawJwt token = RawJwt.newBuilder().addBooleanClaim("boolean", true).withoutExpiration().build();
    assertThat(token.isNullClaim("boolean")).isFalse();
  }

  @Test
  public void customClaimNames_success() throws Exception {
    RawJwt token =
        RawJwt.newBuilder()
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
    RawJwt.Builder builder = RawJwt.newBuilder().withoutExpiration();

    builder.setSubject("foo");
    RawJwt fooToken = builder.build();

    builder.setSubject("bar");
    RawJwt barToken = builder.build();

    assertThat(fooToken.getSubject()).isEqualTo("foo");
    assertThat(barToken.getSubject()).isEqualTo("bar");
  }
}
