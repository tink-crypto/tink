// Copyright 2021 Google LLC
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
import java.security.GeneralSecurityException;
import java.util.Optional;

/** Internal-only interface for authenticating and verifying JWT with JWS MAC. */
@Immutable
interface JwtMacInternal {

  /** Computes a MAC, and encodes the JWT and the MAC in the JWS compact serialization format. */
  String computeMacAndEncodeWithKid(RawJwt token, Optional<String> kid)
      throws GeneralSecurityException;

  /** Decodes and verifies a JWT in the JWS compact serialization format. */
  VerifiedJwt verifyMacAndDecode(String compact, JwtValidator validator)
      throws GeneralSecurityException;
}
