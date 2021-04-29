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

import com.google.errorprone.annotations.Immutable;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A <a href="https://tools.ietf.org/html/rfc7519">JSON Web Token</a> (JWT) that can be signed or
 * MAC'ed to obtain a compact JWT.
 * It can also be a token that has been parsed from a compact JWT, but not yet verified.
 */
@Immutable
public final class RawJwt {

  private static final long MAX_TIMESTAMP_VALUE = 253402300799L;  // 31 Dec 9999, 23:59:59 GMT

  @SuppressWarnings("Immutable") // We do not mutate the payload.
  private final JsonObject payload;

  private RawJwt(Builder builder) {
    this.payload = builder.payload.deepCopy();
  }

  private RawJwt(String jsonPayload) throws JwtInvalidException {
    this.payload = JwtFormat.parseJson(jsonPayload);
    validateStringClaim(JwtNames.CLAIM_ISSUER);
    validateStringClaim(JwtNames.CLAIM_SUBJECT);
    validateStringClaim(JwtNames.CLAIM_JWT_ID);
    validateTimestampClaim(JwtNames.CLAIM_EXPIRATION);
    validateTimestampClaim(JwtNames.CLAIM_NOT_BEFORE);
    validateTimestampClaim(JwtNames.CLAIM_ISSUED_AT);
    validateAudienceClaim();
  }

  private void validateStringClaim(String name) throws JwtInvalidException {
    if (!this.payload.has(name)) {
      return;
    }
    if (!this.payload.get(name).isJsonPrimitive()
        || !this.payload.get(name).getAsJsonPrimitive().isString()) {
      throw new JwtInvalidException("invalid JWT payload: claim " + name + " is not a string.");
    }
  }

  private void validateTimestampClaim(String name) throws JwtInvalidException {
    if (!this.payload.has(name)) {
      return;
    }
    if (!this.payload.get(name).isJsonPrimitive()
        || !this.payload.get(name).getAsJsonPrimitive().isNumber()) {
      throw new JwtInvalidException("invalid JWT payload: claim " + name + " is not a number.");
    }
    double timestamp = this.payload.get(name).getAsJsonPrimitive().getAsDouble();
    if ((timestamp > MAX_TIMESTAMP_VALUE) || (timestamp < 0)) {
      throw new JwtInvalidException(
          "invalid JWT payload: claim " + name + " has an invalid timestamp");
    }
  }

  private void validateAudienceClaim() throws JwtInvalidException {
    if (!this.payload.has(JwtNames.CLAIM_AUDIENCE)) {
      return;
    }
    // if aud is a string, convert it to a JsonArray.
    if (this.payload.get(JwtNames.CLAIM_AUDIENCE).isJsonPrimitive()
        && this.payload.get(JwtNames.CLAIM_AUDIENCE).getAsJsonPrimitive().isString()) {
      JsonArray audiences = new JsonArray();
      audiences.add(this.payload.get(JwtNames.CLAIM_AUDIENCE).getAsString());
      this.payload.add(JwtNames.CLAIM_AUDIENCE, audiences);
      return;
    }

    // aud is not a string, it must be an JsonArray of strings.
    // getAudiences makes sure that all entries are strings.
    List<String> audiences = this.getAudiences();
    if (audiences.size() < 1) {
      throw new JwtInvalidException(
          "invalid JWT payload: claim " + JwtNames.CLAIM_AUDIENCE + " is present but empty.");
    }
  }

  static RawJwt fromJsonPayload(String jsonPayload) throws JwtInvalidException {
    return new RawJwt(jsonPayload);
  }

  /** Builder for RawJwt */
  public static final class Builder {
    private final JsonObject payload;

    public Builder() {
      payload = new JsonObject();
    }

    /**
     * Sets the issuer claim that identifies the principal that issued the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public Builder setIssuer(String value) {
      if (!JwtFormat.isValidString(value)) {
        throw new IllegalArgumentException();
      }
      payload.add(JwtNames.CLAIM_ISSUER, new JsonPrimitive(value));
      return this;
    }

    /**
     * Sets the subject claim identifying the principal that is the subject of the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public Builder setSubject(String value) {
      if (!JwtFormat.isValidString(value)) {
        throw new IllegalArgumentException();
      }
      payload.add(JwtNames.CLAIM_SUBJECT, new JsonPrimitive(value));
      return this;
    }

    /**
     * Adds an audience that the JWT is intended for.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public Builder addAudience(String value) {
      if (!JwtFormat.isValidString(value)) {
        throw new IllegalArgumentException();
      }
      JsonArray audiences = new JsonArray();
      if (payload.has(JwtNames.CLAIM_AUDIENCE)) {
        audiences = payload.get(JwtNames.CLAIM_AUDIENCE).getAsJsonArray();
      }
      audiences.add(value);
      payload.add(JwtNames.CLAIM_AUDIENCE, audiences);
      return this;
    }

    /**
     * Sets the JWT ID claim that provides a unique identifier for the JWT.
     *
     * <p>https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public Builder setJwtId(String value) {
      if (!JwtFormat.isValidString(value)) {
        throw new IllegalArgumentException();
      }
      payload.add(JwtNames.CLAIM_JWT_ID, new JsonPrimitive(value));
      return this;
    }

    private void setTimestampClaim(String name, Instant value) {
      long millis = value.toEpochMilli();
      if ((millis > MAX_TIMESTAMP_VALUE * 1000) || (millis < 0)) {
        throw new IllegalArgumentException(
            "timestamp of claim " + name + " is out of range");
      }
      double doubleMillis = millis;
      payload.add(name, new JsonPrimitive(doubleMillis / 1000));
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
      setTimestampClaim(JwtNames.CLAIM_EXPIRATION, value);
      return this;
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
      setTimestampClaim(JwtNames.CLAIM_NOT_BEFORE, value);
      return this;
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
      setTimestampClaim(JwtNames.CLAIM_ISSUED_AT, value);
      return this;
    }

    /** Adds a custom claim of type {@code boolean} to the JWT. */
    public Builder addBooleanClaim(String name, boolean value) {
      JwtNames.validate(name);
      payload.add(name, new JsonPrimitive(value));
      return this;
    }

    /** Adds a custom claim of type {@code double} to the JWT. */
    public Builder addNumberClaim(String name, double value) {
      JwtNames.validate(name);
      payload.add(name, new JsonPrimitive(value));
      return this;
    }

    /** Adds a custom claim of type {@code String} to the JWT. */
    public Builder addStringClaim(String name, String value) {
      if (!JwtFormat.isValidString(value)) {
        throw new IllegalArgumentException();
      }
      JwtNames.validate(name);
      payload.add(name, new JsonPrimitive(value));
      return this;
    }

    /** Adds a custom claim with value null. */
    public Builder addNullClaim(String name) {
      JwtNames.validate(name);
      payload.add(name, JsonNull.INSTANCE);
      return this;
    }

    /** Adds a custom claim encoded in a JSON {@code String} to the JWT. */
    public Builder addJsonObjectClaim(String name, String encodedJsonObject)
        throws JwtInvalidException {
      JwtNames.validate(name);
      payload.add(name, JwtFormat.parseJson(encodedJsonObject));
      return this;
    }

    /** Adds a custom claim encoded in a JSON {@code String} to the JWT. */
    public Builder addJsonArrayClaim(String name, String encodedJsonArray)
        throws JwtInvalidException {
      JwtNames.validate(name);
      payload.add(name, JwtFormat.parseJsonArray(encodedJsonArray));
      return this;
    }

    public RawJwt build() {
      return new RawJwt(this);
    }
  }

  String getJsonPayload() {
    return payload.toString();
  }

  boolean hasBooleanClaim(String name) {
    JwtNames.validate(name);
    return (payload.has(name)
        && payload.get(name).isJsonPrimitive()
        && payload.get(name).getAsJsonPrimitive().isBoolean());
  }

  Boolean getBooleanClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonPrimitive()
        || !payload.get(name).getAsJsonPrimitive().isBoolean()) {
      throw new JwtInvalidException("claim " + name + " is not a boolean");
    }
    return payload.get(name).getAsBoolean();
  }

  boolean hasNumberClaim(String name) {
    JwtNames.validate(name);
    return (payload.has(name)
        && payload.get(name).isJsonPrimitive()
        && payload.get(name).getAsJsonPrimitive().isNumber());
  }

  Double getNumberClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonPrimitive()
        || !payload.get(name).getAsJsonPrimitive().isNumber()) {
      throw new JwtInvalidException("claim " + name + " is not a number");
    }
    return payload.get(name).getAsDouble();
  }

  boolean hasStringClaim(String name) {
    JwtNames.validate(name);
    return (payload.has(name)
        && payload.get(name).isJsonPrimitive()
        && payload.get(name).getAsJsonPrimitive().isString());
  }

  String getStringClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    return getStringClaimInternal(name);
  }

  private String getStringClaimInternal(String name) throws JwtInvalidException {
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonPrimitive()
        || !payload.get(name).getAsJsonPrimitive().isString()) {
      throw new JwtInvalidException("claim " + name + " is not a string");
    }
    return payload.get(name).getAsString();
  }

  boolean isNullClaim(String name) {
    JwtNames.validate(name);
    try {
      return (JsonNull.INSTANCE.equals(payload.get(name)));
    } catch (JsonParseException ex) {
      return false;
    }
  }

  boolean hasJsonObjectClaim(String name) {
    JwtNames.validate(name);
    return (payload.has(name) && payload.get(name).isJsonObject());
  }

  String getJsonObjectClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonObject()) {
      throw new JwtInvalidException("claim " + name + " is not a JSON object");
    }
    return payload.get(name).getAsJsonObject().toString();
  }

  boolean hasJsonArrayClaim(String name) {
    JwtNames.validate(name);
    return (payload.has(name) && payload.get(name).isJsonArray());
  }

  String getJsonArrayClaim(String name) throws JwtInvalidException {
    JwtNames.validate(name);
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonArray()) {
      throw new JwtInvalidException("claim " + name + " is not a JSON array");
    }
    return payload.get(name).getAsJsonArray().toString();
  }

  boolean hasIssuer() {
    return payload.has(JwtNames.CLAIM_ISSUER);
  }

  String getIssuer() throws JwtInvalidException {
    return getStringClaimInternal(JwtNames.CLAIM_ISSUER);
  }

  boolean hasSubject() {
    return payload.has(JwtNames.CLAIM_SUBJECT);
  }

  String getSubject() throws JwtInvalidException {
    return getStringClaimInternal(JwtNames.CLAIM_SUBJECT);
  }

  boolean hasJwtId() {
    return payload.has(JwtNames.CLAIM_JWT_ID);
  }

  String getJwtId() throws JwtInvalidException {
    return getStringClaimInternal(JwtNames.CLAIM_JWT_ID);
  }

  boolean hasAudiences() {
    // If an audience claim is present, it is always a JsonArray with length > 0.
    return payload.has(JwtNames.CLAIM_AUDIENCE);
  }

  List<String> getAudiences() throws JwtInvalidException {
    if (!hasAudiences()) {
      throw new JwtInvalidException("claim aud does not exist");
    }
    if (!payload.get(JwtNames.CLAIM_AUDIENCE).isJsonArray()) {
      throw new JwtInvalidException("claim aud is not a JSON array");
    }

    JsonArray audiences = payload.get(JwtNames.CLAIM_AUDIENCE).getAsJsonArray();
    List<String> result = new ArrayList<>(audiences.size());
    for (int i = 0; i < audiences.size(); i++) {
      if (!audiences.get(i).isJsonPrimitive()
          || !audiences.get(i).getAsJsonPrimitive().isString()) {
        throw new JwtInvalidException(
            String.format("invalid audience: got %s; want a string", audiences.get(i)));
      }
      String audience = audiences.get(i).getAsString();
      result.add(audience);
    }

    return Collections.unmodifiableList(result);
  }

  private Instant getInstant(String name) throws JwtInvalidException {
    if (!payload.has(name)) {
      throw new JwtInvalidException("claim " + name + " does not exist");
    }
    if (!payload.get(name).isJsonPrimitive()
        || !payload.get(name).getAsJsonPrimitive().isNumber()) {
      throw new JwtInvalidException("claim " + name + " is not a timestamp");
    }
    try {
      double millis = payload.get(name).getAsJsonPrimitive().getAsDouble() * 1000;
      return Instant.ofEpochMilli((long) millis);
    } catch (NumberFormatException ex) {
      throw new JwtInvalidException("claim " + name + " is not a timestamp: " + ex);
    }
  }

  boolean hasExpiration() {
    return payload.has(JwtNames.CLAIM_EXPIRATION);
  }

  Instant getExpiration() throws JwtInvalidException {
    return getInstant(JwtNames.CLAIM_EXPIRATION);
  }

  boolean hasNotBefore() {
    return payload.has(JwtNames.CLAIM_NOT_BEFORE);
  }

  Instant getNotBefore() throws JwtInvalidException {
    return getInstant(JwtNames.CLAIM_NOT_BEFORE);
  }

  boolean hasIssuedAt() {
    return payload.has(JwtNames.CLAIM_ISSUED_AT);
  }

  Instant getIssuedAt() throws JwtInvalidException {
    return getInstant(JwtNames.CLAIM_ISSUED_AT);
  }

  /** Returns all custom claim names. */
  Set<String> customClaimNames() {
    HashSet<String> names = new HashSet<>();
    for (String name : this.payload.keySet()) {
      if (!JwtNames.isRegisteredName(name)) {
        names.add(name);
      }
    }
    return Collections.unmodifiableSet(names);
  }
}
