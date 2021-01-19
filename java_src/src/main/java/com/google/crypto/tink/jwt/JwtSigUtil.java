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

import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.subtle.Enums;
import java.security.GeneralSecurityException;
import java.security.spec.EllipticCurve;
import java.util.Objects;

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

  public static Enums.HashType hashForEcdsaAlgorithm(String algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case "ES256":
        return Enums.HashType.SHA256;
      case "ES384":
        return Enums.HashType.SHA384;
      case "ES512":
        return Enums.HashType.SHA512;
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  public static void validateCurve(EllipticCurve curve, String algorithm)
      throws GeneralSecurityException {
    EllipticCurve expectedCurve;
    switch (algorithm) {
      case "ES256":
        expectedCurve = EllipticCurves.getNistP256Params().getCurve();
        break;
      case "ES384":
        expectedCurve = EllipticCurves.getNistP384Params().getCurve();
        break;
      case "ES512":
        expectedCurve = EllipticCurves.getNistP521Params().getCurve();
        break;
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithm);
    }
    if (!Objects.equals(curve, expectedCurve)) {
      throw new GeneralSecurityException(
          "curve mistmatch. Expected '" + expectedCurve + "', got '" + curve + "'");
    }
  }

  public static Enums.HashType hashForPssAlgorithm(String algorithm)
      throws GeneralSecurityException {
    switch (algorithm) {
      case "PS256":
        return Enums.HashType.SHA256;
      case "PS384":
        return Enums.HashType.SHA384;
      case "PS512":
        return Enums.HashType.SHA512;
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }

  public static int saltLengthForPssAlgorithm(String algorithm) throws GeneralSecurityException {
    switch (algorithm) {
      case "PS256":
        return 32;
      case "PS384":
        return 48;
      case "PS512":
        return 64;
      default: // fall out
    }
    throw new GeneralSecurityException("unknown algorithm " + algorithm);
  }
}
