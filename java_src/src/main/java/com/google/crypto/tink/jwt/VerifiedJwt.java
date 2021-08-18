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
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * A decoded and verified <a href="https://tools.ietf.org/html/rfc7519">JSON Web Token</a> (JWT).
 *
 * <p>A new instance of this class is returned as the result of a sucessfully verification of a
 * MACed or signed compact JWT.
 *
 * <p>It gives read-only access all payload claims and a subset of the headers. It does not contain
 * any headers that depend on the key, such as "alg" or "kid". These headers are checked when the
 * signature is verified and should not be read by the user. This ensures that the key can be
 * changed without any changes to the user code.
 */
@Immutable
public final class VerifiedJwt {

  private final RawJwt rawJwt;

  VerifiedJwt(RawJwt rawJwt) {
    this.rawJwt = rawJwt;
  }

  /**
   * Returns the {@code typ} header value. Throws a JwtInvalidException if header is not present.
   */
  public String getTypeHeader() throws JwtInvalidException {
    return this.rawJwt.getTypeHeader();
  }

  /**
   * Returns true iff the {@code typ} header is present.
   */
  public boolean hasTypeHeader() {
    return this.rawJwt.hasTypeHeader();
  }

  /**
   * Returns the {@code iss} claim that identifies the principal that issued the JWT. Throws a
   * JwtInvalidException if no such claim is present.
   */
  public String getIssuer() throws JwtInvalidException {
    return this.rawJwt.getIssuer();
  }

  /**
   * Returns true iff the {@code iss} claim is present.
   */
  public boolean hasIssuer() {
    return this.rawJwt.hasIssuer();
  }

  /**
   * Returns the {@code sub} claim identifying the principal that is the subject of the JWT. Throws
   * a JwtInvalidException if no such claim is present.
   */
  public String getSubject() throws JwtInvalidException {
    return this.rawJwt.getSubject();
  }

  /**
   * Returns true iff the {@code sub} claim is present.
   */
  public boolean hasSubject() {
    return this.rawJwt.hasSubject();
  }

  /**
   * Returns the {@code aud} claim identifying the principals that are the audience of the JWT.
   * Throws a JwtInvalidException if no such claim is present.
   */
  public List<String> getAudiences() throws JwtInvalidException {
    return this.rawJwt.getAudiences();
  }

  /**
   * Returns true iff the {@code aud} claim is present.
   */
  public boolean hasAudiences() {
    return this.rawJwt.hasAudiences();
  }

  /**
   * Returns the {@code jti} claim that provides a unique identifier for the JWT. Throws a
   * JwtInvalidException if no such claim is present.
   */
  public String getJwtId() throws JwtInvalidException {
    return this.rawJwt.getJwtId();
  }

  /**
   * Returns true iff the {@code jti} claim is present.
   */
  public boolean hasJwtId() {
    return this.rawJwt.hasJwtId();
  }

  /**
   * Returns the expiration time claim {@code exp} that identifies the instant on or after which the
   * token MUST NOT be accepted for processing. Throws a JwtInvalidException if no such claim is
   * present.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getExpiration() throws JwtInvalidException  {
    return this.rawJwt.getExpiration();
  }

  /**
   * Returns true iff the {@code exp} claim is present.
   */
  public boolean hasExpiration() {
    return this.rawJwt.hasExpiration();
  }

  /**
   * Returns the not before claim {@code nbf} that identifies the instant before which the token
   * MUST NOT be accepted for processing. Throws a JwtInvalidException if no such claim is
   * present.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getNotBefore() throws JwtInvalidException {
    return this.rawJwt.getNotBefore();
  }

  /**
   * Returns true iff the {@code nbf} claim is present.
   */
  public boolean hasNotBefore() {
    return this.rawJwt.hasNotBefore();
  }

  /**
   * Returns the issued at time claim {@code iat} that identifies the instant at which the JWT was
   * issued. Throws a JwtInvalidException if no such claim is present.
   *
   * <p>This API requires {@link java.time.Instant} which is unavailable on Android until API level
   * 26. To use it on older Android devices, enable API desugaring as shown in
   * https://developer.android.com/studio/write/java8-support#library-desugaring.
   */
  public Instant getIssuedAt() throws JwtInvalidException {
    return this.rawJwt.getIssuedAt();
  }

  /**
   * Returns true iff the {@code iat} claim is present.
   */
  public boolean hasIssuedAt() {
    return this.rawJwt.hasIssuedAt();
  }

  /**
   * Returns the non-registered claim of name {@code name} and type Boolean. Throws a
   * JwtInvalidException if no such claim is present or the claim has another type.
   */
  public Boolean getBooleanClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getBooleanClaim(name);
  }

  /**
   * Returns the non-registered claim of name {@code name} and type Number. Throws a
   * JwtInvalidException if no such claim is present or the claim has another type.
   */
  public Double getNumberClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getNumberClaim(name);
  }

  /**
   * Returns the non-registered claim of name {@code name} and type String. Throws a
   * JwtInvalidException if no such claim is present or the claim has another type.
   */
  public String getStringClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getStringClaim(name);
  }

  /** Returns true iff there is a non-registered claim of name {@code name} and type NULL. */
  public boolean isNullClaim(String name) {
    return this.rawJwt.isNullClaim(name);
  }

  /**
   * Returns the non-registered claim of name {@code name} and type JSON Object encoded in a string.
   * Throws a JwtInvalidException if no such claim is present or the claim has another type.
   */
  public String getJsonObjectClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getJsonObjectClaim(name);
  }

  /**
   * Returns the non-registered claim of name {@code name} and type JSON Array encoded in a string.
   * Throws a JwtInvalidException if no such claim is present or the claim has another type.
   */
  public String getJsonArrayClaim(String name) throws JwtInvalidException {
    return this.rawJwt.getJsonArrayClaim(name);
  }

  /**
   * Returns true iff a non-registered claim of name {@code name} and type boolean is present.
   */
  public boolean hasBooleanClaim(String name) {
    return this.rawJwt.hasBooleanClaim(name);
  }

  /**
   * Returns true iff a non-registered claim of name {@code name} and type number is present.
   */
  public boolean hasNumberClaim(String name) {
    return this.rawJwt.hasNumberClaim(name);
  }

  /**
   * Returns true iff a non-registered claim of name {@code name} and type string is present.
   */
  public boolean hasStringClaim(String name) {
    return this.rawJwt.hasStringClaim(name);
  }

  /**
   * Returns true iff a non-registered claim of name {@code name} and type JsonObject is present.
   */
  public boolean hasJsonObjectClaim(String name) {
    return this.rawJwt.hasJsonObjectClaim(name);
  }

  /**
   * Returns true iff a non-registered claim of name {@code name} and type JsonArray is present.
   */
  public boolean hasJsonArrayClaim(String name) {
    return this.rawJwt.hasJsonArrayClaim(name);
  }

  /**
   * Returns all non-registered claim names.
   */
  public Set<String> customClaimNames() {
    return this.rawJwt.customClaimNames();
  }
}
