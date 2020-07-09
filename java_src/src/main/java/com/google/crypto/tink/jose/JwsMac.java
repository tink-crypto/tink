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

package com.google.crypto.tink.jose;

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;

/**
 * Interface for JSON Web Signature (JWS) Message Authentication Code (MAC), as described in RFC
 * 7515.
 *
 * <h3>Security guarantees: similar to {@link com.google.crypto.tink.Mac}.</h3>
 */
@Immutable
public interface JwsMac {
  /** Computes a MAC and encodes a JWT in JWS compact serialization format. */
  String computeMacThenEncode(Jwt payload) throws GeneralSecurityException;

  /** Verifies a MAC and decodes a JWT in JWS compact serialization format. */
  Jwt verifyMacThenDecode(String compact) throws GeneralSecurityException;
}
