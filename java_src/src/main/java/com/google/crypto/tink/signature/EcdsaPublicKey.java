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
import com.google.crypto.tink.Key;
import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * EcdsaPublicKey represents the public portion of ECDSA signature primitive.
 *
 * <p>This API is annotated with Alpha because it is not yet stable and might be changed in the
 * future.
 */
@Alpha
@Immutable
public final class EcdsaPublicKey extends SignaturePublicKey {
  private final EcdsaParameters parameters;
  @SuppressWarnings("Immutable") // ECPoint is immutable
  private final ECPoint publicPoint;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  /** Builder for EcdsaPublicKey. */
  public static class Builder {
    @Nullable private EcdsaParameters parameters = null;
    @Nullable private ECPoint publicPoint = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(EcdsaParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicPoint(ECPoint publicPoint) {
      this.publicPoint = publicPoint;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      if (parameters.getVariant() == EcdsaParameters.Variant.NO_PREFIX) {
        return Bytes.copyFrom(new byte[] {});
      }
      if (parameters.getVariant() == EcdsaParameters.Variant.LEGACY
          || parameters.getVariant() == EcdsaParameters.Variant.CRUNCHY) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
      }
      if (parameters.getVariant() == EcdsaParameters.Variant.TINK) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
      }
      throw new IllegalStateException(
          "Unknown EcdsaParameters.Variant: " + parameters.getVariant());
    }

    public EcdsaPublicKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }
      if (publicPoint == null) {
        throw new GeneralSecurityException("Cannot build without public point");
      }
      EllipticCurvesUtil.checkPointOnCurve(
          publicPoint, parameters.getCurveType().toParameterSpec().getCurve());
      if (parameters.hasIdRequirement() && idRequirement == null) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }
      if (!parameters.hasIdRequirement() && idRequirement != null) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }
      Bytes outputPrefix = getOutputPrefix();
      return new EcdsaPublicKey(parameters, publicPoint, outputPrefix, idRequirement);
    }
  }

  private EcdsaPublicKey(
      EcdsaParameters parameters,
      ECPoint publicPoint,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.publicPoint = publicPoint;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public ECPoint getPublicPoint() {
    return publicPoint;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public EcdsaParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof EcdsaPublicKey)) {
      return false;
    }
    EcdsaPublicKey that = (EcdsaPublicKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return that.parameters.equals(parameters)
        && that.publicPoint.equals(publicPoint)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
