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

import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.spec.ECParameterSpec;
import java.util.Objects;

/** Describes the parameters of an ECDSA signature primitive. */
public final class EcdsaParameters extends SignatureParameters {
  /**
   * Describes details of the ECDSA signature computation.
   *
   * <p>The standard ECDSA key is used for variant "NO_PREFIX". Other variants slightly change how
   * the signature is computed, or add a prefix to every computation depending on the key id.
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant CRUNCHY = new Variant("CRUNCHY");
    public static final Variant LEGACY = new Variant("LEGACY");
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

  /** The encoding used in the signature. */
  @Immutable
  public static final class SignatureEncoding {
    public static final SignatureEncoding IEEE_P1363 = new SignatureEncoding("IEEE_P1363");
    public static final SignatureEncoding DER = new SignatureEncoding("DER");

    private final String name;

    private SignatureEncoding(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The elliptic curve and its parameters. */
  @Immutable
  public static final class CurveType {
    public static final CurveType NIST_P256 =
        new CurveType("NIST_P256", EllipticCurvesUtil.NIST_P256_PARAMS);
    public static final CurveType NIST_P384 =
        new CurveType("NIST_P384", EllipticCurvesUtil.NIST_P384_PARAMS);
    public static final CurveType NIST_P521 =
        new CurveType("NIST_P521", EllipticCurvesUtil.NIST_P521_PARAMS);

    private final String name;
    @SuppressWarnings("Immutable") // ECParameterSpec is immutable
    private final ECParameterSpec spec;

    private CurveType(String name, ECParameterSpec spec) {
      this.name = name;
      this.spec = spec;
    }

    @Override
    public String toString() {
      return name;
    }

    public ECParameterSpec toParameterSpec() {
      return spec;
    }

    public static CurveType fromParameterSpec(ECParameterSpec spec)
        throws GeneralSecurityException {
      if (EllipticCurvesUtil.isSameEcParameterSpec(spec, NIST_P256.toParameterSpec())) {
        return NIST_P256;
      }
      if (EllipticCurvesUtil.isSameEcParameterSpec(spec, NIST_P384.toParameterSpec())) {
        return NIST_P384;
      }
      if (EllipticCurvesUtil.isSameEcParameterSpec(spec, NIST_P521.toParameterSpec())) {
        return NIST_P521;
      }
      throw new GeneralSecurityException("unknown ECParameterSpec");
    }
  }

  /** The Hash algorithm used. */
  @Immutable
  public static final class HashType {
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

  /** Builds a new EcdsaParameters instance. */
  public static final class Builder {
    private SignatureEncoding signatureEncoding = null;
    private CurveType curveType = null;
    private HashType hashType = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setSignatureEncoding(SignatureEncoding signatureEncoding) {
      this.signatureEncoding = signatureEncoding;
      return this;
    }

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
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    public EcdsaParameters build() throws GeneralSecurityException {
      if (signatureEncoding == null) {
        throw new GeneralSecurityException("signature encoding is not set");
      }
      if (curveType == null) {
        throw new GeneralSecurityException("EC curve type is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("hash type is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("variant is not set");
      }

      if (curveType == CurveType.NIST_P256) {
        if (hashType != HashType.SHA256) {
          throw new GeneralSecurityException("NIST_P256 requires SHA256");
        }
      }
      if (curveType == CurveType.NIST_P384) {
        if (hashType != HashType.SHA384 && hashType != HashType.SHA512) {
          throw new GeneralSecurityException("NIST_P384 requires SHA384 or SHA512");
        }
      }
      if (curveType == CurveType.NIST_P521) {
        if (hashType != HashType.SHA512) {
          throw new GeneralSecurityException("NIST_P521 requires SHA512");
        }
      }
      return new EcdsaParameters(signatureEncoding, curveType, hashType, variant);
    }
  }

  private final SignatureEncoding signatureEncoding;
  private final CurveType curveType;
  private final HashType hashType;
  private final Variant variant;

  private EcdsaParameters(
      SignatureEncoding signatureEncoding,
      CurveType curveType,
      HashType hashType,
      Variant variant) {
    this.signatureEncoding = signatureEncoding;
    this.curveType = curveType;
    this.hashType = hashType;
    this.variant = variant;
  }

  public static Builder builder() {
    return new Builder();
  }

  public SignatureEncoding getSignatureEncoding() {
    return signatureEncoding;
  }

  public CurveType getCurveType() {
    return curveType;
  }

  public HashType getHashType() {
    return hashType;
  }

  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof EcdsaParameters)) {
      return false;
    }
    EcdsaParameters that = (EcdsaParameters) o;
    return that.getSignatureEncoding() == getSignatureEncoding()
        && that.getCurveType() == getCurveType()
        && that.getHashType() == getHashType()
        && that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(EcdsaParameters.class, signatureEncoding, curveType, hashType, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "ECDSA Parameters (variant: "
        + variant
        + ", hashType: "
        + hashType
        + ", encoding: "
        + signatureEncoding
        + ", curve: "
        + curveType
        + ")";
  }
}
