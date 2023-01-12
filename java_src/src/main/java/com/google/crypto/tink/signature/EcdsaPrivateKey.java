// Copyright 2022 Google LLC
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.util.SecretBigInteger;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/**
 * Represents a key for computing ECDSA signatures.
 *
 * <p>ECDSA is defined in http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, section 6.
 *
 * <p>This API is annotated with Alpha because it is not yet stable and might be changed in the
 * future.
 */
@Alpha
@Immutable
public final class EcdsaPrivateKey extends SignaturePrivateKey {
  private final EcdsaPublicKey publicKey;
  private final SecretBigInteger privateValue;

  /** Builder for EcdsaPrivateKey. */
  public static class Builder {
    private EcdsaPublicKey publicKey = null;
    private SecretBigInteger privateValue = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setPublicKey(EcdsaPublicKey publicKey) {
      this.publicKey = publicKey;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPrivateValue(SecretBigInteger privateValue) {
      this.privateValue = privateValue;
      return this;
    }

    private static void validatePrivateValue(
        BigInteger privateValue, ECPoint publicPoint, EcdsaParameters.CurveType curveType)
        throws GeneralSecurityException {
      BigInteger order = curveType.toParameterSpec().getOrder();
      if ((privateValue.signum() <= 0) || (privateValue.compareTo(order) >= 0)) {
        throw new GeneralSecurityException("Invalid private value");
      }
      ECPoint p = EllipticCurvesUtil.multiplyByGenerator(privateValue, curveType.toParameterSpec());
      if (!p.equals(publicPoint)) {
        throw new GeneralSecurityException("Invalid private value");
      }
    }

    @AccessesPartialKey
    public EcdsaPrivateKey build() throws GeneralSecurityException {
      if (publicKey == null) {
        throw new GeneralSecurityException("Cannot build without a ecdsa public key");
      }
      if (privateValue == null) {
        throw new GeneralSecurityException("Cannot build without a private value");
      }
      validatePrivateValue(
          privateValue.getBigInteger(InsecureSecretKeyAccess.get()),
          publicKey.getPublicPoint(),
          publicKey.getParameters().getCurveType());
      return new EcdsaPrivateKey(publicKey, privateValue);
    }
  }

  private EcdsaPrivateKey(EcdsaPublicKey publicKey, SecretBigInteger privateValue) {
    this.publicKey = publicKey;
    this.privateValue = privateValue;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @Override
  public EcdsaParameters getParameters() {
    return publicKey.getParameters();
  }

  @Override
  public EcdsaPublicKey getPublicKey() {
    return publicKey;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBigInteger getPrivateValue() {
    return privateValue;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof EcdsaPrivateKey)) {
      return false;
    }
    EcdsaPrivateKey that = (EcdsaPrivateKey) o;
    return that.publicKey.equalsKey(publicKey)
        && privateValue.equalsSecretBigInteger(that.privateValue);
  }
}
