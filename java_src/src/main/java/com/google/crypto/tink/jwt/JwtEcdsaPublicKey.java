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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.subtle.Base64;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Optional;
import javax.annotation.Nullable;

/** JwtEcdsaPublicKey represents the public portion of JWT ECDSA keys. */
@Immutable
public final class JwtEcdsaPublicKey extends JwtSignaturePublicKey {
  private final JwtEcdsaParameters parameters;

  @SuppressWarnings("Immutable") // ECPoint is immutable
  private final ECPoint publicPoint;

  private final Optional<String> kid;
  private final Optional<Integer> idRequirement;

  /** Builder for EcdsaPublicKey. */
  public static class Builder {
    private Optional<JwtEcdsaParameters> parameters = Optional.empty();
    private Optional<ECPoint> publicPoint = Optional.empty();
    private Optional<Integer> idRequirement = Optional.empty();
    private Optional<String> customKid = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(JwtEcdsaParameters parameters) {
      this.parameters = Optional.of(parameters);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicPoint(ECPoint publicPoint) {
      this.publicPoint = Optional.of(publicPoint);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(Integer idRequirement) {
      this.idRequirement = Optional.of(idRequirement);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setCustomKid(String customKid) {
      this.customKid = Optional.of(customKid);
      return this;
    }

    private Optional<String> computeKid() throws GeneralSecurityException {
      if (parameters
          .get()
          .getKidStrategy()
          .equals(JwtEcdsaParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException(
              "customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
        }
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement.get()).array();
        return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
      }
      if (parameters.get().getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.CUSTOM)) {
        if (!customKid.isPresent()) {
          throw new GeneralSecurityException("customKid needs to be set for KidStrategy CUSTOM");
        }
        return customKid;
      }
      if (parameters.get().getKidStrategy().equals(JwtEcdsaParameters.KidStrategy.IGNORED)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException("customKid must not be set for KidStrategy IGNORED");
        }
        return Optional.empty();
      }
      throw new IllegalStateException("Unknown kid strategy");
    }

    private static ECParameterSpec parameterSpecFor(JwtEcdsaParameters.Algorithm algorithm)
        throws GeneralSecurityException {
      if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES256)) {
        return EllipticCurvesUtil.NIST_P256_PARAMS;
      }
      if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES384)) {
        return EllipticCurvesUtil.NIST_P384_PARAMS;
      }
      if (algorithm.equals(JwtEcdsaParameters.Algorithm.ES512)) {
        return EllipticCurvesUtil.NIST_P521_PARAMS;
      }
      throw new GeneralSecurityException("Unknown algorithm: " + algorithm);
    }

    public JwtEcdsaPublicKey build() throws GeneralSecurityException {
      if (!parameters.isPresent()) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }
      if (!publicPoint.isPresent()) {
        throw new GeneralSecurityException("Cannot build without public point");
      }
      EllipticCurvesUtil.checkPointOnCurve(
          publicPoint.get(), parameterSpecFor(parameters.get().getAlgorithm()).getCurve());
      if (parameters.get().hasIdRequirement() && !idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }
      if (!parameters.get().hasIdRequirement() && idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }
      return new JwtEcdsaPublicKey(
          parameters.get(), publicPoint.get(), computeKid(), idRequirement);
    }
  }

  private JwtEcdsaPublicKey(
      JwtEcdsaParameters parameters,
      ECPoint publicPoint,
      Optional<String> kid,
      Optional<Integer> idRequirement) {
    this.parameters = parameters;
    this.publicPoint = publicPoint;
    this.kid = kid;
    this.idRequirement = idRequirement;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public ECPoint getPublicPoint() {
    return publicPoint;
  }

  @Override
  public Optional<String> getKid() {
    return kid;
  }

  @Nullable
  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement.orElse(null);
  }

  @Override
  public JwtSignatureParameters getParameters() {
    return parameters;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtEcdsaPublicKey)) {
      return false;
    }
    JwtEcdsaPublicKey that = (JwtEcdsaPublicKey) o;
    return that.parameters.equals(parameters)
        && that.publicPoint.equals(publicPoint)
        && that.kid.equals(kid);
  }
}
