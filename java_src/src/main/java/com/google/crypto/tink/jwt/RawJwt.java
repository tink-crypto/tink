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

import com.google.errorprone.annotations.Immutable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A <a href="https://tools.ietf.org/html/rfc7519">JSON Web Token</a> (JWT) that can be signed or
 * MAC'ed to obtain a compact JWT.
 * It can also be a token that has been parsed from a compact JWT, but not yet verified.
 */
@Immutable
public final class RawJwt {

  @SuppressWarnings("Immutable") // We do not mutate the payload.
  private final JSONObject payload;

  private RawJwt(Builder builder) {
    this.payload = builder.payload;
  }

  /** Builder for RawJwt */
  public static final class Builder {
    private final JSONObject payload;

    public Builder() {
      payload = new JSONObject();
    }

    Builder(String jsonPayload) throws JwtInvalidException {
      try {
        this.payload = new JSONObject(jsonPayload);
      } catch (JSONException ex) {
        throw new JwtInvalidException("invalid JWT payload: " + ex);
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

    /** Adds a custom claim of type {@code boolean} to the JWT. */
    public Builder addBooleanClaim(String name, boolean value) {
      JwtNames.validate(name);
      return setPayload(name, value);
    }

    /** Adds a custom claim of type {@code double} to the JWT. */
    public Builder addNumberClaim(String name, double value) {
      JwtNames.validate(name);
      return setPayload(name, value);
    }

    /** Adds a custom claim of type {@code String} to the JWT. */
    public Builder addStringClaim(String name, String value) {
      JwtNames.validate(name);
      return setPayload(name, value);
    }

    /** Adds a custom claim with value null. */
    public Builder addNullClaim(String name) {
      JwtNames.validate(name);
      return setPayload(name, JSONObject.NULL);
    }

    /** Adds a custom claim encoded in a JSON {@code String} to the JWT. */
    public Builder addJsonObjectClaim(String name, String encodedJsonObject)
        throws JwtInvalidException {
      JwtNames.validate(name);
      try {
        JSONObject jsonObject = new JSONObject(encodedJsonObject);
        return setPayload(name, jsonObject);
      } catch (JSONException ex) {
        throw new JwtInvalidException("Invalid JSON Object: " + ex.getMessage());
      }
    }

    /** Adds a custom claim encoded in a JSON {@code String} to the JWT. */
    public Builder addJsonArrayClaim(String name, String encodedJsonArray)
        throws JwtInvalidException {
      JwtNames.validate(name);
      try {
        JSONArray jsonArray = new JSONArray(encodedJsonArray);
        return setPayload(name, jsonArray);
      } catch (JSONException ex) {
        throw new JwtInvalidException("Invalid JSON Array: " + ex.getMessage());
      }
    }

    public RawJwt build() {
      return new RawJwt(this);
    }
  }

  // TODO(juerg): Replace by a method that returns the encoded payload instead.
  JSONObject getPayload() {
    return payload;
  }

  // TODO(juerg): This should be removed, as we don't want to return Json objects directly.
  Object getClaim(String name) {
    try {
      return payload.get(name);
    } catch (JSONException ex) {
      return null;
    }
  }

  Boolean getBooleanClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    try {
      return (Boolean) payload.get(name);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + name + ": " + ex.getMessage());
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  Double getNumberClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    try {
      return (Double) payload.get(name);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + name + ": " + ex.getMessage());
    } catch (JSONException ex) {
     // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  String getStringClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    try {
      return (String) payload.get(name);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + name + ": " + ex.getMessage());
    } catch (JSONException ex) {
     // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  boolean isNullClaim(String name) {
    try {
      return (JSONObject.NULL.equals(payload.get(name)));
    } catch (JSONException ex) {
      return false;
    }
  }

  String getJsonObjectClaim(String name) throws JwtInvalidException {
    try {
      JSONObject claim = (JSONObject) payload.get(name);
      return claim.toString();
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + name + ": " + ex.getMessage());
    } catch (JSONException ex) {
     // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  String getJsonArrayClaim(String name) throws JwtInvalidException {
    try {
      JSONArray claim = (JSONArray) payload.get(name);
      return claim.toString();
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + name + ": " + ex.getMessage());
    } catch (JSONException ex) {
     // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  String getIssuer() throws JwtInvalidException {
    try {
      return (String) payload.get(JwtNames.CLAIM_ISSUER);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + JwtNames.CLAIM_ISSUER + ": " + ex.getMessage());
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  String getSubject() throws JwtInvalidException {
    try {
      return (String) payload.get(JwtNames.CLAIM_SUBJECT);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + JwtNames.CLAIM_SUBJECT + ": " + ex.getMessage());
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  String getJwtId() throws JwtInvalidException {
    try {
      return (String) payload.get(JwtNames.CLAIM_JWT_ID);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + JwtNames.CLAIM_JWT_ID + ": " + ex.getMessage());
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
      return null;
    }
  }

  List<String> getAudiences() throws JwtInvalidException {
    JSONArray audiences;
    try {
      audiences = (JSONArray) payload.get(JwtNames.CLAIM_AUDIENCE);
    } catch (ClassCastException ex) {
      throw new JwtInvalidException("claim " + JwtNames.CLAIM_AUDIENCE + ": " + ex.getMessage());
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
      return null;
    }

    List<String> result = new ArrayList<>(audiences.length());
    for (int i = 0; i < audiences.length(); i++) {
      try {
        String audience = (String) audiences.get(i);
        result.add(audience);
      } catch (ClassCastException | JSONException ex) {
        throw new JwtInvalidException("invalid audience: " + ex.getMessage());
      }
    }

    return Collections.unmodifiableList(result);
  }

  private Instant getInstant(String name) {
    try {
      return Instant.ofEpochSecond(payload.getLong(name));
    } catch (JSONException ex) {
      // TODO(juerg): throw an exception instead.
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

  /** Returns all custom claim names. */
  Set<String> customClaimNames() {
    HashSet<String> names = new HashSet<>();

    // The following is an unchecked conversion in server Java, but not in android Java.
    // We cannot suppress both warnings.
    Iterator<String> payloadIterator = this.payload.keys();
    while (payloadIterator.hasNext()) {
      String name = payloadIterator.next();
      if (!JwtNames.isRegisteredName(name)) {
        names.add(name);
      }
    }
    return Collections.unmodifiableSet(names);
  }
}
