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
 * Describes the parameters of a {@link RsaSsaPkcs1PublicKey} and {@link RsaSsaPkcs1PrivateKey}.
 *
 * <p>Standard: https://www.rfc-editor.org/rfc/rfc8017.txt
 */
public final class RsaSsaPkcs1Parameters extends SignatureParameters {
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

  /** Builds a new RsaSsaPkcs1Parameters instance. */
  public static final class Builder {
    @Nullable private Integer modulusSizeBits = null;
    @Nullable private BigInteger publicExponent = F4;
    @Nullable private HashType hashType = null;
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
    public Builder setHashType(HashType hashType) {
      this.hashType = hashType;
      return this;
    }

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger PUBLIC_EXPONENT_UPPER_BOUND = TWO.pow(256);

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

    public RsaSsaPkcs1Parameters build() throws GeneralSecurityException {
      if (modulusSizeBits == null) {
        throw new GeneralSecurityException("key size is not set");
      }
      if (publicExponent == null) {
        throw new GeneralSecurityException("publicExponent is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("hash type is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("variant is not set");
      }
      if (modulusSizeBits < 2048) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size in bytes %d; must be at least 2048 bits", modulusSizeBits));
      }
      validatePublicExponent(publicExponent);
      return new RsaSsaPkcs1Parameters(modulusSizeBits, publicExponent, variant, hashType);
    }
  }

  private final int modulusSizeBits;
  private final BigInteger publicExponent;
  private final Variant variant;
  private final HashType hashType;

  private RsaSsaPkcs1Parameters(
      int modulusSizeBits, BigInteger publicExponent, Variant variant, HashType hashType) {
    this.modulusSizeBits = modulusSizeBits;
    this.publicExponent = publicExponent;
    this.variant = variant;
    this.hashType = hashType;
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

  public HashType getHashType() {
    return hashType;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof RsaSsaPkcs1Parameters)) {
      return false;
    }
    RsaSsaPkcs1Parameters that = (RsaSsaPkcs1Parameters) o;
    return that.getModulusSizeBits() == getModulusSizeBits()
        && Objects.equals(that.getPublicExponent(), getPublicExponent())
        && that.getVariant() == getVariant()
        && that.getHashType() == getHashType();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        RsaSsaPkcs1Parameters.class, modulusSizeBits, publicExponent, variant, hashType);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "RSA SSA PKCS1 Parameters (variant: "
        + variant
        + ", hashType: "
        + hashType
        + ", publicExponent: "
        + publicExponent
        + ", and "
        + modulusSizeBits
        + "-bit modulus)";
  }
}
