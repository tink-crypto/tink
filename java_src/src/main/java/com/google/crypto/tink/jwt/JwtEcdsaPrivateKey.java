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

package com.google.crypto.tink.jwt;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/**
 * Represents a key for computing JWT ECDSA signatures (ES256, ES384, ES512).
 *
 * <p>See https://datatracker.ietf.org/doc/html/rfc7518 for more information.
 */
@Immutable
public final class JwtEcdsaPrivateKey extends JwtSignaturePrivateKey {
  public final JwtEcdsaPublicKey publicKey;
  public final SecretBigInteger privateKeyValue;

  private static void validatePrivateValue(
      BigInteger privateValue, ECPoint publicPoint, JwtEcdsaParameters.Algorithm algorithm)
      throws GeneralSecurityException {
    BigInteger order = algorithm.getECParameterSpec().getOrder();
    if ((privateValue.signum() <= 0) || (privateValue.compareTo(order) >= 0)) {
      throw new GeneralSecurityException("Invalid private value");
    }
    ECPoint p =
        EllipticCurvesUtil.multiplyByGenerator(privateValue, algorithm.getECParameterSpec());
    if (!p.equals(publicPoint)) {
      throw new GeneralSecurityException("Invalid private value");
    }
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @AccessesPartialKey
  public static JwtEcdsaPrivateKey create(
      JwtEcdsaPublicKey publicKey, SecretBigInteger privateValue) throws GeneralSecurityException {
    validatePrivateValue(
        privateValue.getBigInteger(InsecureSecretKeyAccess.get()),
        publicKey.getPublicPoint(),
        publicKey.getParameters().getAlgorithm());
    return new JwtEcdsaPrivateKey(publicKey, privateValue);
  }

  private JwtEcdsaPrivateKey(JwtEcdsaPublicKey publicKey, SecretBigInteger privateKeyValue) {
    this.publicKey = publicKey;
    this.privateKeyValue = privateKeyValue;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBigInteger getPrivateValue() {
    return privateKeyValue;
  }

  @Override
  public JwtEcdsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public JwtEcdsaPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtEcdsaPrivateKey)) {
      return false;
    }
    JwtEcdsaPrivateKey that = (JwtEcdsaPrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && privateKeyValue.equalsSecretBigInteger(that.privateKeyValue);
  }
}
