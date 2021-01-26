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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(juerg): Add validation and tests for StringOrURI.

/** Unit tests for RawJwt */
@RunWith(JUnit4.class)
public final class RawJwtTest {

  @Test
  public void noIssuer_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getClaim(JwtNames.CLAIM_ISSUER)).isNull();
  }

  @Test
  public void setIssuer_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setIssuer("foo").build();

    assertThat(token.getClaim(JwtNames.CLAIM_ISSUER)).isEqualTo("foo");
  }

  @Test
  public void noAudience_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getClaim(JwtNames.CLAIM_AUDIENCE)).isNull();
    assertThat(token.getAudiences()).isNull();
  }

  @Test
  public void addAudience_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addAudience("foo").build();
    JSONArray audiences = (JSONArray) token.getClaim(JwtNames.CLAIM_AUDIENCE);

    assertThat(audiences.getString(0)).isEqualTo("foo");
    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void addMulitpleAudiences_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addAudience("foo").addAudience("bar").build();
    JSONArray audiences = (JSONArray) token.getClaim(JwtNames.CLAIM_AUDIENCE);

    assertThat(audiences.getString(0)).isEqualTo("foo");
    assertThat(audiences.getString(1)).isEqualTo("bar");
    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void noSubject_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getClaim(JwtNames.CLAIM_SUBJECT)).isNull();
  }

  @Test
  public void setUnsetSubject_returnsNull() throws Exception {
    RawJwt token = new RawJwt.Builder().setSubject("foo").setSubject(null).build();

    assertThat(token.getClaim(JwtNames.CLAIM_SUBJECT)).isNull();
  }

  @Test
  public void setSubject_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setSubject("foo").build();

    assertThat(token.getClaim(JwtNames.CLAIM_SUBJECT)).isEqualTo("foo");
  }

  @Test
  public void noJwtId_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getClaim(JwtNames.CLAIM_JWT_ID)).isNull();
  }

  @Test
  public void setJwtId_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setJwtId("foo").build();

    assertThat(token.getClaim(JwtNames.CLAIM_JWT_ID)).isEqualTo("foo");
  }

  @Test
  public void addClaim_issuer_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_ISSUER, "blah"));
  }

  @Test
  public void addClaim_subject_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_SUBJECT, "blah"));
  }

  @Test
  public void addClaim_audience_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_AUDIENCE, "blah"));
  }

  @Test
  public void addClaim_jwtId_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_JWT_ID, "blah"));
  }

  @Test
  public void addClaim_expiration_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_EXPIRATION, Instant.now()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_EXPIRATION, 1234567));
  }

  @Test
  public void addClaim_issuedAt_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_ISSUED_AT, Instant.now()));
  }

  @Test
  public void addClaim_notBefore_shouldThrow() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> new RawJwt.Builder().addClaim(JwtNames.CLAIM_NOT_BEFORE, Instant.now()));
  }

  @Test
  public void addClaim_string_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addClaim("claim", "value").build();

    assertThat(token.getClaim("claim")).isEqualTo("value");
  }

  @Test
  public void addClaim_integer_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addClaim("claim", 1).build();

    assertThat(token.getClaim("claim")).isEqualTo(1);
  }

  @Test
  public void addClaim_long_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addClaim("claim", 1L).build();

    assertThat(token.getClaim("claim")).isEqualTo(1L);
  }

  @Test
  public void addClaim_double_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addClaim("claim", 123.4).build();

    assertThat(token.getClaim("claim")).isEqualTo(123.4);
  }

  @Test
  public void addClaim_boolean_success() throws Exception {
    RawJwt token = new RawJwt.Builder().addClaim("claim", true).build();

    assertThat(token.getClaim("claim")).isEqualTo(true);
  }

  @Test
  public void getUnknownClaim_returnsNull() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getClaim("claim")).isNull();
  }

  @Test
  public void addJsonArrayClaim_success() throws Exception {
    JSONArray collection = new JSONArray()
        .put(true)
        .put(123)
        .put(456L)
        .put(123.456)
        .put("value")
        .put(new JSONArray().put(1).put(2));

    RawJwt token = new RawJwt.Builder().addClaim("collection", collection).build();

    JSONArray output = (JSONArray) token.getClaim("collection");
    assertThat(output.length()).isEqualTo(6);
    assertThat(output.getBoolean(0)).isTrue();
    assertThat(output.getInt(1)).isEqualTo(123);
    assertThat(output.getLong(2)).isEqualTo(456L);
    assertThat(output.getDouble(3)).isEqualTo(123.456);
    assertThat(output.getString(4)).isEqualTo("value");
    JSONArray nestedOutput = output.getJSONArray(5);
    assertThat(nestedOutput.length()).isEqualTo(2);
    assertThat(nestedOutput.getInt(0)).isEqualTo(1);
    assertThat(nestedOutput.getInt(1)).isEqualTo(2);
  }

  @Test
  public void addJsonObjectClaim_success() throws Exception {
    JSONObject obj = new JSONObject()
        .put("boolean", false)
        .put("obj1", new JSONObject().put("obj2", new JSONObject().put("42", 42)));

    RawJwt token = new RawJwt.Builder().addClaim("obj", obj).build();

    JSONObject output = (JSONObject) token.getClaim("obj");
    assertThat(output.getBoolean("boolean")).isFalse();
    assertThat(output.getJSONObject("obj1").getJSONObject("obj2").getInt("42")).isEqualTo(42);

    // The behaviour of output.getString("boolean") is inconsistent.

    // In google3 and on android, this returns a string "false".
    // see: https://developer.android.com/reference/org/json/JSONObject#getString(java.lang.String)
    // and: https://source.corp.google.com/piper///depot/google3/third_party/java_src/j2objc/jre_emul/android/platform/libcore/json/src/main/java/org/json/JSONObject.java;l=559

    // But with the maven implementation, this throws an error.
    // see: https://javadoc.io/doc/org.json/json/latest/index.html
    // and: https://github.com/stleary/JSON-java/blob/e33f463179ddb6b5d68eabf24528d94af2d0886b/src/main/java/org/json/JSONObject.java#L858
  }

  @Test
  public void noExpiration_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getExpiration()).isNull();
  }

  @Test
  public void setExpiration_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setExpiration(instant).build();

    assertThat(token.getExpiration()).isEqualTo(instant.truncatedTo(SECONDS));
  }

  @Test
  public void noNotBefore_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getNotBefore()).isNull();
  }

  @Test
  public void setNotBefore_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setNotBefore(instant).build();

    assertThat(token.getNotBefore()).isEqualTo(instant.truncatedTo(SECONDS));
  }

  @Test
  public void noIssuedAt_success() throws Exception {
    RawJwt token = new RawJwt.Builder().build();

    assertThat(token.getIssuedAt()).isNull();
  }

  @Test
  public void setIssuedAt_success() throws Exception {
    Instant instant = Instant.now();
    RawJwt token = new RawJwt.Builder().setIssuedAt(instant).build();

    assertThat(token.getIssuedAt()).isEqualTo(instant.truncatedTo(SECONDS));
  }

  @Test
  public void getPayload_success() throws Exception {
    RawJwt token = new RawJwt.Builder().setJwtId("blah").build();
    JSONObject playload = token.getPayload();
    assertThat(playload.get(JwtNames.CLAIM_JWT_ID)).isEqualTo("blah");
  }

  @Test
  public void fromJsonString_success() throws Exception {
    String input = "{\"jid\": \"abc123\", \"aud\": [\"me\", \"you\"], \"custom\": "
        + " {\"int\": 123, \"string\": \"value\"}}";

    RawJwt token = new RawJwt.Builder(new JSONObject(input)).build();
    assertThat(token.getClaim("jid")).isEqualTo("abc123");
    assertThat(token.getAudiences()).containsExactly("me", "you");

    JSONObject custom = (JSONObject) token.getClaim("custom");
    assertThat(custom.getInt("int")).isEqualTo(123);
    assertThat(custom.getString("string")).isEqualTo("value");
  }
}
