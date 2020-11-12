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
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JwtFormat */
@RunWith(JUnit4.class)
public final class JwtFormatTest {

  @Test
  public void createDecodeHeader_success() throws Exception {
    JSONObject header = JwtFormat.decodeHeader(JwtFormat.createHeader("RS256"));
    assertThat(header.getString("alg")).isEqualTo("RS256");
  }

  @Test
  public void createHeaderWithUnknownAlgorithm_fails() throws Exception {
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> JwtFormat.createHeader("UnknownAlgorithm"));
  }

  @Test
  public void decodeHeaderA1_success() throws Exception {
    // Example from https://tools.ietf.org/html/rfc7515#appendix-A.1
    JSONObject header = JwtFormat.decodeHeader("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
    assertThat(header.getString("typ")).isEqualTo("JWT");
    assertThat(header.getString("alg")).isEqualTo("HS256");
  }

  @Test
  public void decodeHeaderA2_success() throws Exception {
    // Example from https://tools.ietf.org/html/rfc7515#appendix-A.2
    JSONObject header = JwtFormat.decodeHeader("eyJhbGciOiJSUzI1NiJ9");
    assertThat(header.getString("alg")).isEqualTo("RS256");
  }

  @Test
  public void decodeInvalidHeader_fail() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> JwtFormat.decodeHeader("INVALID!!!"));
  }

  @Test
  public void createDecodeValidateHeader_success() throws Exception {
    JwtFormat.validateHeader("HS256", JwtFormat.decodeHeader(JwtFormat.createHeader("HS256")));
    JwtFormat.validateHeader("HS384", JwtFormat.decodeHeader(JwtFormat.createHeader("HS384")));
    JwtFormat.validateHeader("HS512", JwtFormat.decodeHeader(JwtFormat.createHeader("HS512")));
    JwtFormat.validateHeader("ES256", JwtFormat.decodeHeader(JwtFormat.createHeader("ES256")));
    JwtFormat.validateHeader("RS256", JwtFormat.decodeHeader(JwtFormat.createHeader("RS256")));
  }

  @Test
  public void validateHeaderWithWrongAlgorithm_fails() throws Exception {
    JSONObject header = JwtFormat.decodeHeader(JwtFormat.createHeader("HS256"));
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> JwtFormat.validateHeader("HS384", header));
  }

  @Test
  public void validateHeaderWithUnknownAlgorithm_fails() throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", "UnknownAlgorithm");
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> JwtFormat.validateHeader("UnknownAlgorithm", header));
  }

  @Test
  public void validateHeaderWithValidLowercaseTyp_success() throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", "HS256");
    header.put("typ", "jwt");
    JwtFormat.validateHeader("HS256", header);
  }

  @Test
  public void validateHeaderWithBadTyp_fails() throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", "HS256");
    header.put("typ", "IWT");
    assertThrows(
        JwtInvalidException.class,
        () -> JwtFormat.validateHeader("HS256", header));
  }

  @Test
  public void validateHeaderWithUnknownEntry_fails() throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", "HS256");
    header.put("unknown", "header");
    assertThrows(
        JwtInvalidException.class,
        () -> JwtFormat.validateHeader("HS256", header));
  }

  @Test
  public void validateEmptyHeader_fails() throws Exception {
    JSONObject emptyHeader = new JSONObject();
    assertThrows(
        JwtInvalidException.class,
        () -> JwtFormat.validateHeader("HS256", emptyHeader));
  }

  @Test
  public void encodeDecodePayload_equal() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("iss", "joe");
    payload.put("exp", 1300819380);
    payload.put("http://example.com/is_root", true);
    String encodedPayload = JwtFormat.encodePayload(payload);
    JSONObject decodedPayload = JwtFormat.decodePayload(encodedPayload);
    assertThat(decodedPayload.getString("iss")).isEqualTo("joe");
    assertThat(decodedPayload.getInt("exp")).isEqualTo(1300819380);
    assertThat(decodedPayload.getBoolean("http://example.com/is_root")).isTrue();
  }

  @Test
  public void decodePayload_success() throws Exception {
    // Example from https://tools.ietf.org/html/rfc7515#appendix-A.1
    JSONObject payload =
        JwtFormat.decodePayload(
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
                + "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ");
    assertThat(payload.getString("iss")).isEqualTo("joe");
    assertThat(payload.getInt("exp")).isEqualTo(1300819380);
    assertThat(payload.getBoolean("http://example.com/is_root")).isTrue();
  }

  @Test
  public void decodeInvalidPayload_fails() throws Exception {
    assertThrows(
        JwtInvalidException.class,
        () -> JwtFormat.decodePayload("INVALID!!!"));
  }

  @Test
  public void createUnsignedCompact_success() throws Exception {
    JSONObject payload = new JSONObject();
    payload.put("iss", "joe");
    assertThat(JwtFormat.createUnsignedCompact("RS256", payload)).isEqualTo(
            "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UifQ");
  }

  @Test
  public void encodeDecodeSignature_success() throws Exception {
    // Example from https://tools.ietf.org/html/rfc7515#appendix-A.1
    byte[] signatureBytes =
        new byte[] {
          (byte) 116,
          (byte) 24,
          (byte) 223,
          (byte) 180,
          (byte) 151,
          (byte) 153,
          (byte) 224,
          (byte) 37,
          (byte) 79,
          (byte) 250,
          (byte) 96,
          (byte) 125,
          (byte) 216,
          (byte) 173,
          (byte) 187,
          (byte) 186,
          (byte) 22,
          (byte) 212,
          (byte) 37,
          (byte) 77,
          (byte) 105,
          (byte) 214,
          (byte) 191,
          (byte) 240,
          (byte) 91,
          (byte) 88,
          (byte) 5,
          (byte) 88,
          (byte) 83,
          (byte) 132,
          (byte) 141,
          (byte) 121
        };
    String encodeSignature = JwtFormat.encodeSignature(signatureBytes);
    assertThat(encodeSignature)
        .isEqualTo("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assertThat(JwtFormat.decodeSignature(encodeSignature))
        .isEqualTo(signatureBytes);
  }
}
