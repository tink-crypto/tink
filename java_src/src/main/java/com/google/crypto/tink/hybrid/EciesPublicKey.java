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
  private final Bytes publicPointBytes;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private EciesPublicKey(
      EciesParameters parameters,
      Bytes publicPointBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.publicPointBytes = publicPointBytes;
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

  private static EllipticCurves.PointFormatType getPointFormatType(
      EciesParameters.PointFormat pointFormat) {
    if (pointFormat == EciesParameters.PointFormat.COMPRESSED) {
      return EllipticCurves.PointFormatType.COMPRESSED;
    }
    if (pointFormat == EciesParameters.PointFormat.UNCOMPRESSED) {
      return EllipticCurves.PointFormatType.UNCOMPRESSED;
    }
    if (pointFormat == EciesParameters.PointFormat.LEGACY_UNCOMPRESSED) {
      return EllipticCurves.PointFormatType.DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
    }

    throw new IllegalArgumentException("Unable to determine point format type for " + pointFormat);
  }

  private static void validatePublicPoint(
      EciesParameters.CurveType curveType,
      EciesParameters.PointFormat pointFormat,
      Bytes publicPointBytes)
      throws GeneralSecurityException {
    /*
     * Every 32-byte string is accepted as a Curve25519 public key. See also:
     * https://cr.yp.to/ecdh/curve25519-20060209.pdf
     */
    if (curveType == EciesParameters.CurveType.X25519) {
      if (publicPointBytes.size() != 32) {
        throw new GeneralSecurityException(
            "Encoded public point byte length for X25519 curve must be 32");
      }
      return;
    }

    // Validation for Nist Curve public points.
    EllipticCurve curve = getParameterSpecNistCurve(curveType);
    EllipticCurves.PointFormatType pointFormatType = getPointFormatType(pointFormat);

    // This checks if the point is on the curve and if the encoding has the proper length.
    ECPoint unused =
        EllipticCurves.pointDecode(curve, pointFormatType, publicPointBytes.toByteArray());
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
   * Creates a new ECIES public key.
   *
   * @param parameters ECIES parameters for the public key
   * @param publicPointBytes public point coordinates in bytes. For the NIST curves, the public
   *     point is encoded using the Elliptic-Curve-Point-to-Octet-String conversion according to
   *     https://secg.org/sec1-v2.pdf. For X25519, the encoding is just the identity function, since
   *     these curves already use fixed-length byte strings for public keys.
   * @param idRequirement key id requirement, which must be null for {@code NO_PREFIX} variant and
   *     non-null for all other variants
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static EciesPublicKey create(
      EciesParameters parameters, Bytes publicPointBytes, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validateIdRequirement(parameters.getVariant(), idRequirement);
    validatePublicPoint(
        parameters.getCurveType(), parameters.getNistCurvePointFormat(), publicPointBytes);

    Bytes prefix = createOutputPrefix(parameters.getVariant(), idRequirement);

    return new EciesPublicKey(parameters, publicPointBytes, prefix, idRequirement);
  }

  /**
   * Returns the underlying public point coordinates as {@code Bytes}, using the
   * Octet-String-to-Elliptic-Curve-Point conversion according to https://secg.org/sec1-v2.pdf (for
   * the NIST curves). For X25519, the decoding is just the identity function.
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public Bytes getPublicPointBytes() {
    return publicPointBytes;
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
        && publicPointBytes.equals(other.publicPointBytes)
        && Objects.equals(idRequirement, other.idRequirement);
  }
}
