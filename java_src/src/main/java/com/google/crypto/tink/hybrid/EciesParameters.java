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

import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.AesCtrHmacAeadParameters;
import com.google.crypto.tink.aead.AesGcmParameters;
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters;
import com.google.crypto.tink.daead.AesSivParameters;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nullable;

/**
 * Parameters for an ECIES primitive with HKDF and AEAD encryption.
 *
 * <p>This API follows loosely ECIES ISO 18033-2 standard (Elliptic Curve Integrated Encryption
 * Scheme, see http://www.shoup.net/iso/std6.pdf), but with some differences:
 *
 * <ul>
 *   <li>use of HKDF key derivation function (instead of KDF1 and KDF2) enabling the use of optional
 *       parameters to the key derivation function, which strenghten the overall security and allow
 *       for binding the key material to application-specific information (see RFC 5869)
 *   <li>use of modern AEAD/Deterministic AEAD schemes rather than "manual composition" of symmetric
 *       encryption with message authentication codes (as in DEM1, DEM2, and DEM3 schemes of ISO
 *       18033-2)
 * </ul>
 */
public final class EciesParameters extends HybridParameters {
  private static Set<Parameters> listAcceptedDemParameters() throws GeneralSecurityException {
    HashSet<Parameters> acceptedDemParameters = new HashSet<>();
    // AES128_GCM_RAW
    acceptedDemParameters.add(
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(16)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build());
    // AES256_GCM_RAW
    acceptedDemParameters.add(
        AesGcmParameters.builder()
            .setIvSizeBytes(12)
            .setKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setVariant(AesGcmParameters.Variant.NO_PREFIX)
            .build());
    // AES128_CTR_HMAC_SHA256_RAW
    acceptedDemParameters.add(
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(16)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(16)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build());
    // AES256_CTR_HMAC_SHA256_RAW
    acceptedDemParameters.add(
        AesCtrHmacAeadParameters.builder()
            .setAesKeySizeBytes(32)
            .setHmacKeySizeBytes(32)
            .setTagSizeBytes(32)
            .setIvSizeBytes(16)
            .setHashType(AesCtrHmacAeadParameters.HashType.SHA256)
            .setVariant(AesCtrHmacAeadParameters.Variant.NO_PREFIX)
            .build());
    // XCHACHA20_POLY1305_RAW
    acceptedDemParameters.add(XChaCha20Poly1305Parameters.create());
    // AES256_SIV_RAW
    acceptedDemParameters.add(
        AesSivParameters.builder()
            .setKeySizeBytes(64)
            .setVariant(AesSivParameters.Variant.NO_PREFIX)
            .build());
    return Collections.unmodifiableSet(acceptedDemParameters);
  }

  private static final Set<Parameters> acceptedDemParameters =
      exceptionIsBug(() -> listAcceptedDemParameters());

  /** Description of the output prefix prepended to the ciphertext. */
  @Immutable
  public static final class Variant {
    /** Leading 0x01-byte followed by 4-byte key id (big endian format). */
    public static final Variant TINK = new Variant("TINK");

    /** Leading 0x00-byte followed by 4-byte key id (big endian format). */
    public static final Variant CRUNCHY = new Variant("CRUNCHY");

    /** Empty prefix. */
    public static final Variant NO_PREFIX = new Variant("NO_PREFIX");

    private final String name;

    private Variant(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The elliptic curve type used for the KEM. */
  @Immutable
  public static final class CurveType {
    public static final CurveType NIST_P256 = new CurveType("NIST_P256");
    public static final CurveType NIST_P384 = new CurveType("NIST_P384");
    public static final CurveType NIST_P521 = new CurveType("NIST_P521");
    public static final CurveType X25519 = new CurveType("X25519");

    private final String name;

    private CurveType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The Hash algorithm used for the KEM. */
  @Immutable
  public static final class HashType {
    public static final HashType SHA1 = new HashType("SHA1");
    public static final HashType SHA224 = new HashType("SHA224");
    public static final HashType SHA256 = new HashType("SHA256");
    public static final HashType SHA384 = new HashType("SHA384");
    public static final HashType SHA512 = new HashType("SHA512");

    private final String name;

    private HashType(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The Elliptic Curve Point Format. */
  @Immutable
  public static final class PointFormat {
    public static final PointFormat COMPRESSED = new PointFormat("COMPRESSED");
    public static final PointFormat UNCOMPRESSED = new PointFormat("UNCOMPRESSED");

    /**
     * Like {@code UNCOMPRESSED}, but without the \x04 prefix. Crunchy uses this format. DO NOT USE
     * unless you are a Crunchy user moving to Tink.
     */
    public static final PointFormat LEGACY_UNCOMPRESSED = new PointFormat("LEGACY_UNCOMPRESSED");

    private final String name;

    private PointFormat(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** Builds a new {@link EciesParameters} instance. */
  public static final class Builder {
    private CurveType curveType = null;
    private HashType hashType = null;
    private PointFormat nistCurvePointFormat = null;
    private Parameters demParameters = null;
    private Variant variant = Variant.NO_PREFIX;
    @Nullable private Bytes salt = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setCurveType(CurveType curveType) {
      this.curveType = curveType;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setHashType(HashType hashType) {
      this.hashType = hashType;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setNistCurvePointFormat(PointFormat pointFormat) {
      this.nistCurvePointFormat = pointFormat;
      return this;
    }

    /**
     * Current implementation only accepts certain NO_PREFIX instances of AesGcmParameters,
     * AesCtrHmacAeadParameters, XChaCha20Poly1305Parameters or AesSivParameters.
     */
    @CanIgnoreReturnValue
    public Builder setDemParameters(Parameters demParameters) throws GeneralSecurityException {
      if (!acceptedDemParameters.contains(demParameters)) {
        throw new GeneralSecurityException(
            "Invalid DEM parameters "
                + demParameters
                + "; only AES128_GCM_RAW, AES256_GCM_RAW, AES128_CTR_HMAC_SHA256_RAW,"
                + " AES256_CTR_HMAC_SHA256_RAW XCHACHA20_POLY1305_RAW and AES256_SIV_RAW are"
                + " currently supported.");
      }
      
      this.demParameters = demParameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    /** Defaults to null if not set. */
    @CanIgnoreReturnValue
    public Builder setSalt(Bytes salt) {
      if (salt.size() == 0) {
        this.salt = null;
        return this;
      }

      this.salt = salt;
      return this;
    }

    public EciesParameters build() throws GeneralSecurityException {
      if (curveType == null) {
        throw new GeneralSecurityException("Elliptic curve type is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("Hash type is not set");
      }
      if (demParameters == null) {
        throw new GeneralSecurityException("DEM parameters are not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("Variant is not set");
      }

      if (curveType != CurveType.X25519 && nistCurvePointFormat == null) {
        throw new GeneralSecurityException("Point format is not set");
      }
      if (curveType == CurveType.X25519 && nistCurvePointFormat != null) {
        throw new GeneralSecurityException("For Curve25519 point format must not be set");
      }
      return new EciesParameters(
          curveType, hashType, nistCurvePointFormat, demParameters, variant, salt);
    }
  }

  private final CurveType curveType;
  private final HashType hashType;
  @Nullable private final PointFormat nistCurvePointFormat;
  private final Variant variant;
  private final Parameters demParameters;
  @Nullable private final Bytes salt;

  private EciesParameters(
      CurveType curveType,
      HashType hashType,
      @Nullable PointFormat pointFormat,
      Parameters demParameters,
      Variant variant,
      Bytes salt) {
    this.curveType = curveType;
    this.hashType = hashType;
    this.nistCurvePointFormat = pointFormat;
    this.demParameters = demParameters;
    this.variant = variant;
    this.salt = salt;
  }

  public static Builder builder() {
    return new Builder();
  }

  public CurveType getCurveType() {
    return curveType;
  }

  public HashType getHashType() {
    return hashType;
  }

  public PointFormat getNistCurvePointFormat() {
    return nistCurvePointFormat;
  }

  public Parameters getDemParameters() {
    return demParameters;
  }

  public Variant getVariant() {
    return variant;
  }

  /**
   * Gets the salt value, which defaults to null if not set.
   *
   * <p>This class does not store an RFC compliant default value and the converion must be done in
   * the implementation (meaning that a null salt must be converted to a string of zeros that is of
   * the length of the hash function output, as per RFC 5869).
   */
  @Nullable
  public Bytes getSalt() {
    return salt;
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof EciesParameters)) {
      return false;
    }
    EciesParameters that = (EciesParameters) o;
    return Objects.equals(that.getCurveType(), getCurveType())
        && Objects.equals(that.getHashType(), getHashType())
        && Objects.equals(that.getNistCurvePointFormat(), getNistCurvePointFormat())
        && Objects.equals(that.getDemParameters(), getDemParameters())
        && Objects.equals(that.getVariant(), getVariant())
        && Objects.equals(that.getSalt(), getSalt());
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        EciesParameters.class,
        curveType,
        hashType,
        nistCurvePointFormat,
        demParameters,
        variant,
        salt);
  }

  @Override
  public String toString() {
    return String.format(
        "EciesParameters(curveType=%s, hashType=%s, pointFormat=%s, demParameters=%s, variant=%s,"
            + " salt=%s)",
        curveType, hashType, nistCurvePointFormat, demParameters, variant, salt);
  }
}
