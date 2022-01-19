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
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Interface for creating a signed JWT, as described in RFC 7519 and RFC 7515.
 *
 * <h3>Security guarantees: similar to {@link com.google.crypto.tink.PublicKeySign}.</h3>
 */
@Immutable
public interface JwtPublicKeySignInternal {
  /**
   * Computes a signature, and encodes the JWT and the signature in the JWS compact serialization
   * format.
   */
  String signAndEncodeWithKid(RawJwt token, Optional<String> kid) throws GeneralSecurityException;
}
