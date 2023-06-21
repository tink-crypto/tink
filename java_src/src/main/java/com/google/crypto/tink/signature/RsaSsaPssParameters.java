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

package com.google.crypto.tink.signature;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of a {@link RsaSsaPssPublicKey} and {@link RsaSsaPssPrivateKey}.
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc8017#section-8.1
 */
public final class RsaSsaPssParameters extends SignatureParameters {
  /**
   * Describes details of the signature.
   *
   * <p>The usual key is used for variant "NO_PREFIX". Other variants slightly change how the
   * signature is computed, or add a prefix to every computation depending on the key id.
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

  public static final BigInteger F4 = BigInteger.valueOf(65537);

  /** Builds a new RsaSsaPssParameters instance. */
  public static final class Builder {
    @Nullable private Integer modulusSizeBits = null;
    @Nullable private BigInteger publicExponent = F4;
    @Nullable private HashType sigHashType = null;
    @Nullable private HashType mgf1HashType = null;
    @Nullable private Integer saltLengthBytes = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setModulusSizeBits(int modulusSizeBits) {
      this.modulusSizeBits = modulusSizeBits;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicExponent(BigInteger e) {
      this.publicExponent = e;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSigHashType(HashType sigHashType) {
      this.sigHashType = sigHashType;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setMgf1HashType(HashType mgf1HashType) {
      this.mgf1HashType = mgf1HashType;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setSaltLengthBytes(int saltLengthBytes) throws GeneralSecurityException {
      if (saltLengthBytes < 0) {
        throw new GeneralSecurityException(
            String.format(
                "Invalid salt length in bytes %d; salt length must be positive", saltLengthBytes));
      }
      this.saltLengthBytes = saltLengthBytes;
      return this;
    }

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger PUBLIC_EXPONENT_UPPER_BOUND = TWO.pow(256);
    private static final int MIN_RSA_MODULUS_SIZE = 2048;

    private void validatePublicExponent(BigInteger publicExponent)
        throws InvalidAlgorithmParameterException {
      // We use the validation of the public exponent as defined in
      // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, B.3
      int c = publicExponent.compareTo(F4);
      if (c == 0) {
        // publicExponent is F4.
        return;
      }
      if (c < 0) {
        // publicExponent is smaller than F4.
        throw new InvalidAlgorithmParameterException("Public exponent must be at least 65537.");
      }
      if (publicExponent.mod(TWO).equals(BigInteger.ZERO)) {
        // publicExponent is even. This is invalid since it is not co-prime to p-1.
        throw new InvalidAlgorithmParameterException("Invalid public exponent");
      }
      if (publicExponent.compareTo(PUBLIC_EXPONENT_UPPER_BOUND) > 0) {
        // publicExponent is larger than PUBLIC_EXPONENT_UPPER_BOUND.
        throw new InvalidAlgorithmParameterException(
            "Public exponent cannot be larger than 2^256.");
      }
    }

    public RsaSsaPssParameters build() throws GeneralSecurityException {
      if (modulusSizeBits == null) {
        throw new GeneralSecurityException("key size is not set");
      }
      if (publicExponent == null) {
        throw new GeneralSecurityException("publicExponent is not set");
      }
      if (sigHashType == null) {
        throw new GeneralSecurityException("signature hash type is not set");
      }
      if (mgf1HashType == null) {
        throw new GeneralSecurityException("mgf1 hash type is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("variant is not set");
      }
      if (saltLengthBytes == null) {
        throw new GeneralSecurityException("salt length is not set");
      }
      if (modulusSizeBits < MIN_RSA_MODULUS_SIZE) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size in bytes %d; must be at least %d bits",
                modulusSizeBits, MIN_RSA_MODULUS_SIZE));
      }
      if (sigHashType != mgf1HashType) {
        throw new GeneralSecurityException("MGF1 hash is different from signature hash");
      }
      validatePublicExponent(publicExponent);
      return new RsaSsaPssParameters(
          modulusSizeBits, publicExponent, variant, sigHashType, mgf1HashType, saltLengthBytes);
    }
  }

  private final int modulusSizeBits;
  private final BigInteger publicExponent;
  private final Variant variant;
  private final HashType sigHashType;
  private final HashType mgf1HashType;
  private final int saltLengthBytes;

  private RsaSsaPssParameters(
      int modulusSizeBits,
      BigInteger publicExponent,
      Variant variant,
      HashType sigHashType,
      HashType mgf1HashType,
      int saltLengthBytes) {
    this.modulusSizeBits = modulusSizeBits;
    this.publicExponent = publicExponent;
    this.variant = variant;
    this.sigHashType = sigHashType;
    this.mgf1HashType = mgf1HashType;
    this.saltLengthBytes = saltLengthBytes;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getModulusSizeBits() {
    return modulusSizeBits;
  }

  public BigInteger getPublicExponent() {
    return publicExponent;
  }

  public Variant getVariant() {
    return variant;
  }

  public HashType getSigHashType() {
    return sigHashType;
  }

  public HashType getMgf1HashType() {
    return mgf1HashType;
  }

  public int getSaltLengthBytes() {
    return saltLengthBytes;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof RsaSsaPssParameters)) {
      return false;
    }
    RsaSsaPssParameters that = (RsaSsaPssParameters) o;
    return that.getModulusSizeBits() == getModulusSizeBits()
        && Objects.equals(that.getPublicExponent(), getPublicExponent())
        && Objects.equals(that.getVariant(), getVariant())
        && Objects.equals(that.getSigHashType(), getSigHashType())
        && Objects.equals(that.getMgf1HashType(), getMgf1HashType())
        && that.getSaltLengthBytes() == getSaltLengthBytes();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        RsaSsaPssParameters.class,
        modulusSizeBits,
        publicExponent,
        variant,
        sigHashType,
        mgf1HashType,
        saltLengthBytes);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "RSA SSA PSS Parameters (variant: "
        + variant
        + ", signature hashType: "
        + sigHashType
        + ", mgf1 hashType: "
        + mgf1HashType
        + ", saltLengthBytes: "
        + saltLengthBytes
        + ", publicExponent: "
        + publicExponent
        + ", and "
        + modulusSizeBits
        + "-bit modulus)";
  }
}
