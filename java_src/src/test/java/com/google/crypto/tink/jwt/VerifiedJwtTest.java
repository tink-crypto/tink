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

/** Unit tests for Jwt */
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
  public void getNotRegisteredClaim_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("string", "issuer");
    payload.put("int", 123);
    payload.put("bool", true);

    VerifiedJwt token = new VerifiedJwt(payload);
    assertThat(token.getClaim("bool")).isEqualTo(true);
    assertThat(token.getClaim("string")).isEqualTo("issuer");
    assertThat(token.getClaim("int")).isEqualTo(123);
  }

  @Test
  public void nonExpiredToken_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_EXPIRATION, 1234567);
    VerifiedJwt token = new VerifiedJwt(payload);

    assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1234567));

    assertThat(token.getIssuer()).isNull();
    assertThat(token.getSubject()).isNull();
    assertThat(token.getAudiences()).isNull();
    assertThat(token.getJwtId()).isNull();
    assertThat(token.getNotBefore()).isNull();
    assertThat(token.getIssuedAt()).isNull();
    assertThat(token.getClaim("blah")).isNull();
  }

  @Test
  public void notBeforeToken_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put(JwtNames.CLAIM_NOT_BEFORE, 1234567);
    VerifiedJwt notBeforeToken = new VerifiedJwt(payload);

    assertThat(notBeforeToken.getNotBefore()).isEqualTo(Instant.ofEpochSecond(1234567));

    assertThat(notBeforeToken.getIssuer()).isNull();
    assertThat(notBeforeToken.getSubject()).isNull();
    assertThat(notBeforeToken.getAudiences()).isNull();
    assertThat(notBeforeToken.getJwtId()).isNull();
    assertThat(notBeforeToken.getExpiration()).isNull();
    assertThat(notBeforeToken.getIssuedAt()).isNull();
    assertThat(notBeforeToken.getClaim("blah")).isNull();
  }
}
