// Copyright 2023 Google LLC
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

package com.google.crypto.tink.apps.paymentmethodtoken;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.SecretKeyAccess;
import com.google.crypto.tink.jwt.JwtEcdsaParameters;
import com.google.crypto.tink.jwt.JwtEcdsaPrivateKey;
import com.google.crypto.tink.jwt.JwtEcdsaPublicKey;
import com.google.crypto.tink.subtle.Base64;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.SecretBigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * Functions that convert raw keys into Tink JWT Signature keys.
 *
 * <p>These functions are currently just an example, and are not (yet) part of the public API.
 */
final class JwtKeyConverter {

  /**
   * Converts an uncompressed Base64 encoded ECDSA public key for NIST P-256 Curve into a Tink
   * JwtEcdsaPublicKey with algorithm ES256.
   */
  @AccessesPartialKey
  static JwtEcdsaPublicKey fromBase64EncodedNistP256PublicKey(
      String based64EncodedEcNistP256PublicKey) throws GeneralSecurityException {
    ECPublicKey ecPublicKey =
        EllipticCurves.getEcPublicKey(
            EllipticCurves.CurveType.NIST_P256,
            EllipticCurves.PointFormatType.UNCOMPRESSED,
            Base64.decode(based64EncodedEcNistP256PublicKey));
    JwtEcdsaParameters parameters =
        JwtEcdsaParameters.builder()
            .setKidStrategy(JwtEcdsaParameters.KidStrategy.IGNORED)
            .setAlgorithm(JwtEcdsaParameters.Algorithm.ES256)
            .build();
    return JwtEcdsaPublicKey.builder()
        .setParameters(parameters)
        .setPublicPoint(ecPublicKey.getW())
        .build();
  }

  /**
   * Converts a Base64 encoded PKCS8 ECDSA private key for NIST P-256 Curve into a Tink
   * JwtEcdsaPrivateKey with algorithm ES256.
   *
   * <p>It also requires that you provide the corresponding JwtEcdsaPublicKey.
   */
  @AccessesPartialKey
  static JwtEcdsaPrivateKey fromBased64EncodedPkcs8EcNistP256PrivateKey(
      String based64EncodedPkcs8EcNistP256PrivateKey,
      JwtEcdsaPublicKey publicKey,
      SecretKeyAccess access)
      throws GeneralSecurityException {
    if (publicKey.getParameters().getAlgorithm() != JwtEcdsaParameters.Algorithm.ES256) {
      throw new GeneralSecurityException("Only ES256 is supported.");
    }
    if (publicKey.getParameters().getKidStrategy() != JwtEcdsaParameters.KidStrategy.IGNORED) {
      throw new GeneralSecurityException("Only KidStrategy IGNORED is supported.");
    }
    ECPrivateKey ecPrivateKey =
        EllipticCurves.getEcPrivateKey(Base64.decode(based64EncodedPkcs8EcNistP256PrivateKey));
    return JwtEcdsaPrivateKey.create(
        publicKey, SecretBigInteger.fromBigInteger(ecPrivateKey.getS(), access));
  }

  private JwtKeyConverter() {}
}
