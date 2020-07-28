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

import com.google.crypto.tink.subtle.Base64;
import com.google.errorprone.annotations.Immutable;
import java.nio.charset.Charset;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A <a href="https://tools.ietf.org/html/rfc7519">JSON Web Token</a> (JWT) that can be signed or
 * MAC'ed to obtain a compact JWT.
 */
@Immutable
public final class ToBeSignedJwt {
  private static final Charset UTF_8 = Charset.forName("UTF-8");

  @SuppressWarnings("Immutable") // We do not mutate the header.
  private final JSONObject header;

  @SuppressWarnings("Immutable") // We do not mutate the payload.
  private final JSONObject payload;

  private ToBeSignedJwt(Builder builder) {
    this.header = builder.header;
    this.payload = builder.payload;
  }

  /** Builder for ToBeSignedJwt */
  public static final class Builder {
    private final JSONObject header;
    private final JSONObject payload;

    public Builder() {
      header = new JSONObject();
      payload = new JSONObject();
    }

    Builder(String compact) {
      String[] parts = compact.split("\\.");
      if (parts.length != 2) {
        throw new IllegalArgumentException(
            "invalid compact JWT; must contain exactly 1 dot, but got " + compact);
      }

      try {
        this.header = new JSONObject(new String(Base64.urlSafeDecode(parts[0]), UTF_8));
      } catch (JSONException ex) {
        throw new IllegalArgumentException("invalid JWT header: " + ex);
      }

      try {
        this.payload = new JSONObject(new String(Base64.urlSafeDecode(parts[1]), UTF_8));
      } catch (JSONException ex) {
        throw new IllegalArgumentException("invalid JWT payload: " + ex);
      }
    }

    private Builder setHeader(String name, String value) {
      try {
        header.put(name, value);
        return this;
      } catch (JSONException ex) {
        throw new IllegalArgumentException(ex);
      }
    }

    private Builder setPayload(String name, Object value) {
      try {
        payload.put(name, value);
        return this;
      } catch (JSONException ex) {
        throw new IllegalArgumentException(ex);
      }
    }

    /**
     * Sets the type of this JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-5.1
     */
    public Builder setType(String value) {
      return setHeader(JwtNames.HEADER_TYPE, value);
    }

    /**
     * Sets the content type header parameter used to declare structural information about the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-5.2
     */
    public Builder setContentType(String value) {
      return setHeader(JwtNames.HEADER_CONTENT_TYPE, value);
    }

    /**
     * Sets the name of the algorithm used to sign or authenticate the JWT.
     *
     * <p>This is not a public method because Tink will add the correct algorithm name based on the
     * key type.
     */
    Builder setAlgorithm(String value) {
      return setHeader(JwtNames.HEADER_ALGORITHM, validateAlgorithm(value));
    }

    private static String validateAlgorithm(String algo) {
      switch (algo) {
        case "HS256":
        case "HS384":
        case "HS512":
        case "ES256":
        case "RS256":
          return algo;
        default:
          throw new IllegalArgumentException("invalid algorithm: " + algo);
      }
    }

    /**
     * Sets the ID of the key used to sign or authenticate the JWT.
     *
     * <p>While Tink ignores this ID, other implementations might require it.
     */
    public Builder setKeyId(String value) {
      return setHeader(JwtNames.HEADER_KEY_ID, value);
    }

    /**
     * Sets the issuer claim that identifies the principal that issued the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder setIssuer(String value) {
      return setPayload(JwtNames.CLAIM_ISSUER, value);
    }

    /**
     * Sets the subject claim identifying the principal that is the subject of the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public Builder setSubject(String value) {
      return setPayload(JwtNames.CLAIM_SUBJECT, value);
    }

    /**
     * Adds an audience that the JWT is intended for.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public Builder addAudience(String value) {
      JSONArray audiences;
      try {
        audiences = payload.getJSONArray(JwtNames.CLAIM_AUDIENCE);
      } catch (JSONException ex) {
        audiences = new JSONArray();
      }

      audiences.put(value);
      return setPayload(JwtNames.CLAIM_AUDIENCE, audiences);
    }

    /**
     * Sets the JWT ID claim that provides a unique identifier for the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public Builder setJwtId(String value) {
      return setPayload(JwtNames.CLAIM_JWT_ID, value);
    }

    /**
     * Sets the {@code exp} claim that identifies the instant on or after which the token MUST NOT
     * be accepted for processing.
     *
     * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API
     * level 26. To use it on older Android devices, enable API desugaring as shown in
     * https://developer.android.com/studio/write/java8-support#library-desugaring.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.4
     */
    public Builder setExpiration(Instant value) {
      return setPayload(JwtNames.CLAIM_EXPIRATION, value.getEpochSecond());
    }

    /**
     * Sets the {@code nbf} claim that identifies the instant before which the token MUST NOT be
     * accepted for processing.
     *
     * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API
     * level 26. To use it on older Android devices, enable API desugaring as shown in
     * https://developer.android.com/studio/write/java8-support#library-desugaring.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.5
     */
    public Builder setNotBefore(Instant value) {
      return setPayload(JwtNames.CLAIM_NOT_BEFORE, value.getEpochSecond());
    }

    /**
     * Sets the {@code iat} claim that identifies the instant at which the JWT was issued.
     *
     * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API
     * level 26. To use it on older Android devices, enable API desugaring as shown in
     * https://developer.android.com/studio/write/java8-support#library-desugaring.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.6
     */
    public Builder setIssuedAt(Instant value) {
      return setPayload(JwtNames.CLAIM_ISSUED_AT, value.getEpochSecond());
    }

    /** Adds an arbitrary claim to the JWT. */
    public Builder addClaim(String name, Object value) {
      return setPayload(JwtNames.validate(name), value);
    }

    public ToBeSignedJwt build() {
      return new ToBeSignedJwt(this);
    }
  }

  // These getter methods are not public because we don't want users to accidentally get claims or
  // headers from untrusted JWTs.

  String getHeader(String name) {
    try {
      return header.getString(name);
    } catch (JSONException ex) {
      return null;
    }
  }

  JSONObject getHeader() {
    return header;
  }

  JSONObject getPayload() {
    return payload;
  }

  Object getClaim(String name) {
    try {
      return payload.get(name);
    } catch (JSONException ex) {
      return null;
    }
  }

  String getAlgorithm() {
    try {
      return header.getString(JwtNames.HEADER_ALGORITHM);
    } catch (JSONException ex) {
      throw new IllegalStateException("an alg header is required, but not found", ex);
    }
  }

  List<String> getAudiences() {
    JSONArray audiences = (JSONArray) getClaim(JwtNames.CLAIM_AUDIENCE);
    if (audiences == null) {
      return null;
    }

    List<String> result = new ArrayList<>(audiences.length());
    for (int i = 0; i < audiences.length(); i++) {
      try {
        result.add(audiences.getString(i));
      } catch (JSONException ex) {
        throw new IllegalStateException("invalid audience", ex);
      }
    }

    return Collections.unmodifiableList(result);
  }

  private Instant getInstant(String name) {
    try {
      return Instant.ofEpochSecond(payload.getLong(name));
    } catch (JSONException ex) {
      return null;
    }
  }

  Instant getExpiration() {
    return getInstant(JwtNames.CLAIM_EXPIRATION);
  }

  Instant getNotBefore() {
    return getInstant(JwtNames.CLAIM_NOT_BEFORE);
  }

  Instant getIssuedAt() {
    return getInstant(JwtNames.CLAIM_ISSUED_AT);
  }

  /**
   * Serializes the token in the JWS compact serialization format, described in
   * https://tools.ietf.org/html/rfc7515#section-3.1.
   */
  String compact(String alg) {
    JSONObject copy;

    try {
      copy = new JSONObject(this.header.toString());
      copy.put(JwtNames.HEADER_ALGORITHM, alg);
    } catch (JSONException ex) {
      // Should never happen.
      throw new IllegalStateException(ex);
    }

    String headerStr = Base64.urlSafeEncode(copy.toString().getBytes(UTF_8));
    String payloadStr = Base64.urlSafeEncode(this.payload.toString().getBytes(UTF_8));
    return headerStr + "." + payloadStr;
  }
}
