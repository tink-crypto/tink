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

/** Representation of the encryption function for an HPKE hybrid encryption primitive. */
@Immutable
public final class HpkePublicKey extends HybridPublicKey {
  private final HpkeParameters parameters;
  private final Bytes publicKeyBytes;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  private HpkePublicKey(
      HpkeParameters parameters,
      Bytes publicKeyBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.publicKeyBytes = publicKeyBytes;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  private static void validateIdRequirement(
      HpkeParameters.Variant variant, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    if (!variant.equals(HpkeParameters.Variant.NO_PREFIX) && idRequirement == null) {
      throw new GeneralSecurityException(
          "'idRequirement' must be non-null for " + variant + " variant.");
    }
    if (variant.equals(HpkeParameters.Variant.NO_PREFIX) && idRequirement != null) {
      throw new GeneralSecurityException("'idRequirement' must be null for NO_PREFIX variant.");
    }
  }

  private static void validatePublicKeyByteLength(HpkeParameters.KemId kemId, Bytes publicKeyBytes)
      throws GeneralSecurityException {
    // Key lengths from 'Npk' column in https://www.rfc-editor.org/rfc/rfc9180.html#table-2.
    int keyLengthInBytes = publicKeyBytes.size();
    String parameterizedErrorMessage =
        "Encoded public key byte length for " + kemId + " must be %d, not " + keyLengthInBytes;
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256) {
      if (keyLengthInBytes != 65) {
        throw new GeneralSecurityException(String.format(parameterizedErrorMessage, 65));
      }
      return;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384) {
      if (keyLengthInBytes != 97) {
        throw new GeneralSecurityException(String.format(parameterizedErrorMessage, 97));
      }
      return;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      if (keyLengthInBytes != 133) {
        throw new GeneralSecurityException(String.format(parameterizedErrorMessage, 133));
      }
      return;
    }
    if (kemId == HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256) {
      if (keyLengthInBytes != 32) {
        throw new GeneralSecurityException(String.format(parameterizedErrorMessage, 32));
      }
      return;
    }
    throw new GeneralSecurityException("Unable to validate public key length for " + kemId);
  }

  private static boolean isNistKem(HpkeParameters.KemId kemId) {
    return kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256
        || kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384
        || kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512;
  }

  private static EllipticCurve getNistCurve(HpkeParameters.KemId kemId) {
    if (kemId == HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256) {
      return EllipticCurves.getNistP256Params().getCurve();
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P384_HKDF_SHA384) {
      return EllipticCurves.getNistP384Params().getCurve();
    }
    if (kemId == HpkeParameters.KemId.DHKEM_P521_HKDF_SHA512) {
      return EllipticCurves.getNistP521Params().getCurve();
    }
    throw new IllegalArgumentException("Unable to determine NIST curve type for " + kemId);
  }

  private static void validatePublicKeyOnCurve(HpkeParameters.KemId kemId, Bytes publicKeyBytes)
      throws GeneralSecurityException {
    if (!isNistKem(kemId)) {
      return;
    }
    EllipticCurve curve = getNistCurve(kemId);
    ECPoint point =
        EllipticCurves.pointDecode(
            curve, EllipticCurves.PointFormatType.UNCOMPRESSED, publicKeyBytes.toByteArray());
    EllipticCurvesUtil.checkPointOnCurve(point, curve);
  }

  /**
   * Validate public key according to https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4.
   *
   * <p>Specifically, validate public key lengths and NIST KEM public key values according to
   * Section 5.6.2.3.4 of https://doi.org/10.6028/nist.sp.800-56ar3.
   */
  private static void validatePublicKey(HpkeParameters.KemId kemId, Bytes publicKeyBytes)
      throws GeneralSecurityException {
    validatePublicKeyByteLength(kemId, publicKeyBytes);
    validatePublicKeyOnCurve(kemId, publicKeyBytes);
  }

  private static Bytes createOutputPrefix(
      HpkeParameters.Variant variant, @Nullable Integer idRequirement) {
    if (variant == HpkeParameters.Variant.NO_PREFIX) {
      return Bytes.copyFrom(new byte[] {});
    }
    if (idRequirement == null) {
      throw new IllegalStateException(
          "idRequirement must be non-null for HpkeParameters.Variant " + variant);
    }
    if (variant == HpkeParameters.Variant.CRUNCHY) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
    }
    if (variant == HpkeParameters.Variant.TINK) {
      return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
    }
    throw new IllegalStateException("Unknown HpkeParameters.Variant: " + variant);
  }

  /**
   * Creates a new HPKE public key.
   *
   * @param parameters HPKE parameters for the public key
   * @param publicKeyBytes Public key encoded according to
   *     https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.1
   * @param idRequirement Key id requirement, which must be null for {@code NO_PREFIX} variant and
   *     non-null for all other variants
   */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static HpkePublicKey create(
      HpkeParameters parameters, Bytes publicKeyBytes, @Nullable Integer idRequirement)
      throws GeneralSecurityException {
    validateIdRequirement(parameters.getVariant(), idRequirement);
    validatePublicKey(parameters.getKemId(), publicKeyBytes);
    Bytes prefix = createOutputPrefix(parameters.getVariant(), idRequirement);
    return new HpkePublicKey(parameters, publicKeyBytes, prefix, idRequirement);
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public Bytes getPublicKeyBytes() {
    return publicKeyBytes;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public HpkeParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof HpkePublicKey)) {
      return false;
    }
    HpkePublicKey other = (HpkePublicKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return parameters.equals(other.parameters)
        && publicKeyBytes.equals(other.publicKeyBytes)
        && Objects.equals(idRequirement, other.idRequirement);
  }
}
