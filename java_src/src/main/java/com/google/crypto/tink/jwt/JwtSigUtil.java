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

import com.google.crypto.tink.subtle.Enums;
import java.security.GeneralSecurityException;

final class JwtSigUtil {

  private JwtSigUtil() {}

  public static Enums.HashType hashForPkcs1Algorithm(String algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case "RS256":
        return Enums.HashType.SHA256;
      case "RS384":
        return Enums.HashType.SHA384;
      case "RS512":
        return Enums.HashType.SHA512;
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }
}
