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

final class JwtNames {
  /**
   * Registered claim names, as defined in https://tools.ietf.org/html/rfc7519#section-4.1. If
   * update, please update validateClaim().
   */
  static final String CLAIM_ISSUER = "iss";

  static final String CLAIM_SUBJECT = "sub";
  static final String CLAIM_AUDIENCE = "aud";
  static final String CLAIM_EXPIRATION = "exp";
  static final String CLAIM_NOT_BEFORE = "nbf";
  static final String CLAIM_ISSUED_AT = "iat";
  static final String CLAIM_JWT_ID = "jti";

  /**
   * Supported protected headers, as described in https://tools.ietf.org/html/rfc7515#section-4.1
   */
  static final String HEADER_ALGORITHM = "alg";

  static final String HEADER_KEY_ID = "kid";
  static final String HEADER_TYPE = "typ";
  static final String HEADER_TYPE_VALUE = "JWT";
  static final String HEADER_CONTENT_TYPE = "cty";

  static String validate(String name) {
    if (isRegisteredName(name)) {
      throw new IllegalArgumentException(
          String.format(
              "claim '%s' is invalid because it's a registered name; use the corresponding"
                  + " setter method.",
              name));
    }
    return name;
  }

  static boolean isRegisteredName(String name) {
    return name.equals(CLAIM_ISSUER)
        || name.equals(CLAIM_SUBJECT)
        || name.equals(CLAIM_AUDIENCE)
        || name.equals(CLAIM_EXPIRATION)
        || name.equals(CLAIM_NOT_BEFORE)
        || name.equals(CLAIM_ISSUED_AT)
        || name.equals(CLAIM_JWT_ID);
  }

  private JwtNames() {}
}
