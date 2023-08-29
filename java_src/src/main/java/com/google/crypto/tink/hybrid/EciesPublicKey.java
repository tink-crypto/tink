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

package com.google.crypto.tink.hybrid;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Objects;
import javax.annotation.Nullable;

/** Represents the encryption function for an ECIES hybrid encryption primitive. */
@Immutable
public final class EciesPublicKey extends HybridPublicKey {
  private final EciesParameters parameters;

  /** Exactly one of nistPublicPoint and x25519PublicPointBytes is non-null. */
  @SuppressWarnings("Immutable") // ECPoint is immutable
  @Nullable
  private final ECPoint nistPublicPoint;

  /** Exactly one of nistPublicPoint and x25519PublicPointBytes is non-null. */
  @Nullable private final Bytes x25519PublicPointBytes;

  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private EciesPublicKey(
      EciesParameters parameters,
      @Nullable ECPoint nistPublicPoint,
      @Nullable Bytes x25519PublicPointBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.nistPublicPoint = nistPublicPoint;
    this.x25519PublicPointBytes = x25519PublicPointBytes;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  private static void validateIdRequirement(
      EciesParameters.Variant variant, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!variant.equals(EciesParameters.Variant.NO_PREFIX) && idRequirement == null) {
      throw new GeneralSecurityException(
          "'idRequirement' must be non-null for " + variant + " variant.");
    }
    if (variant.equals(EciesParameters.Variant.NO_PREFIX) && idRequirement != null) {
      throw new GeneralSecurityException("'idRequirement' must be null for NO_PREFIX variant.");
    }
  }

  private static EllipticCurve getParameterSpecNistCurve(EciesParameters.CurveType curveType) {
    if (curveType == EciesParameters.CurveType.NIST_P256) {
      return EllipticCurves.getNistP256Params().getCurve();
    }
    if (curveType == EciesParameters.CurveType.NIST_P384) {
      return EllipticCurves.getNistP384Params().getCurve();
    }
    if (curveType == EciesParameters.CurveType.NIST_P521) {
      return EllipticCurves.getNistP521Params().getCurve();
    }
    throw new IllegalArgumentException("Unable to determine NIST curve type for " + curveType);
  }

  private static Bytes createOutputPrefix(
      EciesParameters.Variant variant, @Nullable Integer idRequirement) {
    if (variant == EciesParameters.Variant.NO_PREFIX) {
      return Bytes.copyFrom(new byte[] {});
    }
    if (idRequirement == null) {
      throw new IllegalStateException(
          "idRequirement must be non-null for EciesParameters.Variant: " + variant);
    }
    if (variant == EciesParameters.Variant.CRUNCHY) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
    }
    if (variant == EciesParameters.Variant.TINK) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
    }
    throw new IllegalStateException("Unknown EciesParameters.Variant: " + variant);
  }

  /**
   * Creates a new ECIES public key using Curve25519.
   *
   * @param parameters ECIES parameters for the public key
   * @param publicPointBytes public point coordinates in bytes.
   * @param idRequirement key id requirement, which must be null for {@code NO_PREFIX} variant and
   *     non-null for all other variants
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static EciesPublicKey createForCurveX25519(
      EciesParameters parameters, Bytes publicPointBytes, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!parameters.getCurveType().equals(EciesParameters.CurveType.X25519)) {
      throw new GeneralSecurityException(
          "createForCurveX25519 may only be called with parameters for curve X25519");
    }
    validateIdRequirement(parameters.getVariant(), idRequirement);
    if (publicPointBytes.size() != 32) {
      throw new GeneralSecurityException(
          "Encoded public point byte length for X25519 curve must be 32");
    }

    Bytes prefix = createOutputPrefix(parameters.getVariant(), idRequirement);

    return new EciesPublicKey(parameters, null, publicPointBytes, prefix, idRequirement);
  }

  /**
   * Creates a new ECIES public key using a NIST Curve.
   *
   * @param parameters ECIES parameters for the public key
   * @param publicPoint public point as a {@code ECPoint}.
   * @param idRequirement key id requirement, which must be null for {@code NO_PREFIX} variant and
   *     non-null for all other variants
   */
  public static EciesPublicKey createForNistCurve(
      EciesParameters parameters, ECPoint publicPoint, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (parameters.getCurveType().equals(EciesParameters.CurveType.X25519)) {
      throw new GeneralSecurityException(
          "createForNistCurve may only be called with parameters for NIST curve");
    }
    validateIdRequirement(parameters.getVariant(), idRequirement);
    EllipticCurvesUtil.checkPointOnCurve(
        publicPoint, getParameterSpecNistCurve(parameters.getCurveType()));

    Bytes prefix = createOutputPrefix(parameters.getVariant(), idRequirement);

    return new EciesPublicKey(parameters, publicPoint, null, prefix, idRequirement);
  }

  /**
   * Returns the underlying public point if the curve is a NIST curve.
   *
   * <p>Returns null if the curve used for this key is not a NIST curve.
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @Nullable
  public ECPoint getNistCurvePoint() {
    return nistPublicPoint;
  }

  /**
   * Returns the underlying public point as EC Point in case the curve is a NIST curve.
   *
   * <p>Returns null for X25519 curves.
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  @Nullable
  public Bytes getX25519CurvePointBytes() {
    return x25519PublicPointBytes;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public EciesParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof EciesPublicKey)) {
      return false;
    }
    EciesPublicKey other = (EciesPublicKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return parameters.equals(other.parameters)
        && Objects.equals(x25519PublicPointBytes, other.x25519PublicPointBytes)
        && Objects.equals(nistPublicPoint, other.nistPublicPoint)
        && Objects.equals(idRequirement, other.idRequirement);
  }
}
