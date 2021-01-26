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
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

// TODO(juerg): Add validation and tests for StringOrURI.

/** Unit tests for VerifiedJwt */
@RunWith(JUnit4.class)
public final class VerifiedJwtTest {
  @Test
  public void emptyJwt_success() throws Exception {
    VerifiedJwt emptyToken = new VerifiedJwt(new JSONObject());

    assertThat(emptyToken.getIssuer()).isNull();
    assertThat(emptyToken.getSubject()).isNull();
    assertThat(emptyToken.getAudiences()).isNull();
    assertThat(emptyToken.getJwtId()).isNull();
    assertThat(emptyToken.getExpiration()).isNull();
    assertThat(emptyToken.getNotBefore()).isNull();
    assertThat(emptyToken.getIssuedAt()).isNull();
    assertThat(emptyToken.getClaim("blah")).isNull();
  }

  @Test
  public void getIssuer_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_ISSUER, "foo");
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getIssuer()).isEqualTo("foo");
  }

  @Test
  public void getSubject_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_SUBJECT, "foo");
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getSubject()).isEqualTo("foo");
  }

  @Test
  public void getAudiences_success() throws Exception {
    JSONObject payload = new JSONObject();
    JSONArray audiences = new JSONArray();
    audiences.put("foo");
    payload.put(JwtNames.CLAIM_AUDIENCE, audiences);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getAudiences()).containsExactly("foo");
  }

  @Test
  public void getMultipleAudiences_success() throws Exception {
    JSONObject payload = new JSONObject();
    JSONArray audiences = new JSONArray();
    audiences.put("foo");
    audiences.put("bar");
    payload.put(JwtNames.CLAIM_AUDIENCE, audiences);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getAudiences()).containsExactly("foo", "bar");
  }

  @Test
  public void getJwtId_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_JWT_ID, "foo");
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getJwtId()).isEqualTo("foo");
  }

  @Test
  public void getJwtIdFromInt_throwsException() throws Exception {
    JSONObject payload = new JSONObject().put(JwtNames.CLAIM_JWT_ID, 1234);
    VerifiedJwt token = new VerifiedJwt(payload);
    // TODO(juerg): Throw a JwtInvalidException on construction of VerifiedJwt or RawJwt.
    assertThrows(ClassCastException.class, token::getJwtId);
  }

  @Test
  public void getJwtIdFromNull_success() throws Exception {
    JSONObject payload = new JSONObject().put(JwtNames.CLAIM_JWT_ID, JSONObject.NULL);
    VerifiedJwt token = new VerifiedJwt(payload);
    assertThrows(ClassCastException.class, token::getJwtId);
  }

  @Test
  public void getExpiration_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_EXPIRATION, 1234567);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getNotBefore_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_NOT_BEFORE, 1234567);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getNotBefore()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

  @Test
  public void getIssuedAt_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_ISSUED_AT, 1234567);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1234567));
  }

 @Test
  public void getRegisteredClaim_shouldThrow() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_EXPIRATION, Instant.now().getEpochSecond());
    payload.put(JwtNames.CLAIM_ISSUER, "issuer");
    payload.put(JwtNames.CLAIM_SUBJECT, "subject");
    payload.put(JwtNames.CLAIM_AUDIENCE, "audience");
    payload.put(JwtNames.CLAIM_ISSUED_AT, Instant.now().getEpochSecond());
    payload.put(JwtNames.CLAIM_NOT_BEFORE, Instant.now().getEpochSecond());
    payload.put(JwtNames.CLAIM_JWT_ID, "id");
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_EXPIRATION));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_ISSUER));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_SUBJECT));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_AUDIENCE));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_ISSUED_AT));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_JWT_ID));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_NOT_BEFORE));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_EXPIRATION));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_EXPIRATION));
    assertThrows(IllegalArgumentException.class, () -> token.getClaim(JwtNames.CLAIM_EXPIRATION));
  }

  @Test
  public void getNotRegisteredSimpleClaims_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("string", "issuer");
    payload.put("int", 123);
    payload.put("bool", true);
    payload.put("long", 456L);
    payload.put("double", 123.456);

    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getClaim("bool")).isEqualTo(true);
    assertThat(token.getClaim("string")).isEqualTo("issuer");
    assertThat(token.getClaim("int")).isEqualTo(123);
    assertThat(token.getClaim("long")).isEqualTo(456L);
    assertThat(token.getClaim("double")).isEqualTo(123.456);
  }

  @Test
  public void getClaimsSetToJsonObjectNull_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("null_object", JSONObject.NULL);
    VerifiedJwt token = new VerifiedJwt(payload);
    assertThat(token.getClaim("null_object")).isNotNull();
    assertThat(token.getClaim("null_object")).isEqualTo(JSONObject.NULL);

    JSONObject payload2 = new JSONObject("{\"null_object\": null}");
    VerifiedJwt token2 = new VerifiedJwt(payload2);
    assertThat(token2.getClaim("null_object")).isNotNull();
    assertThat(token2.getClaim("null_object")).isEqualTo(JSONObject.NULL);
  }

  @Test
  public void getNotRegisteredJsonArrayClaim_success() throws Exception {
    JSONArray collection = new JSONArray()
        .put(true)
        .put(123)
        .put(456L)
        .put(123.456)
        .put("value")
        .put(new JSONArray().put(1).put(2));
    JSONObject payload = new JSONObject()
        .put(JwtNames.CLAIM_JWT_ID, "id")
        .put("collection", collection);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getJwtId()).isEqualTo("id");
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
  public void getNotRegisteredJsonObjectClaim_success() throws Exception {
    JSONObject obj = new JSONObject()
        .put("boolean", false)
        .put("obj1", new JSONObject().put("obj2", new JSONObject().put("42", 42)));
    JSONObject payload = new JSONObject()
        .put(JwtNames.CLAIM_JWT_ID, "id")
        .put("obj", obj);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getJwtId()).isEqualTo("id");
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
  public void fromJsonString_success() throws Exception {
    String input = "{\"jid\": \"abc123\", \"aud\": [\"me\", \"you\"], \"custom\": "
        + " {\"int\": 123, \"string\": \"value\"}}";

    VerifiedJwt token = new VerifiedJwt(new JSONObject(input));
    assertThat(token.getClaim("jid")).isEqualTo("abc123");
    assertThat(token.getAudiences()).containsExactly("me", "you");

    JSONObject custom = (JSONObject) token.getClaim("custom");
    assertThat(custom.getInt("int")).isEqualTo(123);
    assertThat(custom.getString("string")).isEqualTo("value");
  }
}
