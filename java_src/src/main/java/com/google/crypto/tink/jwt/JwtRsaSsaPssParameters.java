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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import java.util.Optional;

/**
 * Describes the parameters of a {@link JwtRsaSsaPssPublicKey} and {@link JwtRsaSsaPssPrivateKey}.
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc7518#section-3.5
 */
public final class JwtRsaSsaPssParameters extends JwtSignatureParameters {
  /** Specifies how the "kid" header is handled. */
  @Immutable
  public static final class KidStrategy {
    /**
     * The "kid" is the URL safe (RFC 4648 Section 5) base64-encoded big-endian key_id in the
     * keyset.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink always adds the KID.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode} Tink checks that the kid is present and equal
     * to this value.
     *
     * <p>This strategy is recommended by Tink.
     */
    public static final KidStrategy BASE64_ENCODED_KEY_ID =
        new KidStrategy("BASE64_ENCODED_KEY_ID");

    /**
     * The "kid" header is ignored.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink does not write a "kid" header.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode} Tink ignores the "kid" header.
     */
    public static final KidStrategy IGNORED = new KidStrategy("IGNORED");

    /**
     * The "kid" is fixed. It can be obtained from {@code parameters.getCustomKid()}.
     *
     * <p>In {@code PublicKeySign#signAndEncode} Tink writes the "kid" header to the value given by
     * {@code parameters.getCustomKid()}.
     *
     * <p>In {@code PublicKeyVerify#verifyAndDecode}, if the kid is present, it needs to match
     * {@code parameters.getCustomKid()}. If the kid is absent, it will be accepted.
     *
     * <p>Note: Tink does not allow to randomly generate new {@link JwtRsaSsaPssKey} objects from
     * parameters objects with {@code KidStrategy} equals to {@code CUSTOM}.
     */
    public static final KidStrategy CUSTOM = new KidStrategy("CUSTOM");

    private final String name;

    private KidStrategy(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /** The algorithm to be used for the signature computation. */
  @Immutable
  public static final class Algorithm {
    /** RSASSA-PSS using SHA-256 and MGF1 with SHA-256 */
    public static final Algorithm PS256 = new Algorithm("PS256");

    /** RSASSA-PSS using SHA-384 and MGF1 with SHA-384 */
    public static final Algorithm PS384 = new Algorithm("PS384");

    /** RSASSA-PSS using SHA-512 and MGF1 with SHA-512 */
    public static final Algorithm PS512 = new Algorithm("PS512");

    private final String name;

    private Algorithm(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }

    public String getStandardName() {
      return name;
    }
  }

  public static final BigInteger F4 = BigInteger.valueOf(65537);

  /** Builds a new JwtRsaSsaPssParameters instance. */
  public static final class Builder {
    Optional<Integer> modulusSizeBits = Optional.empty();
    Optional<BigInteger> publicExponent = Optional.of(F4);
    Optional<KidStrategy> kidStrategy = Optional.empty();
    Optional<Algorithm> algorithm = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setModulusSizeBits(int modulusSizeBits) {
      this.modulusSizeBits = Optional.of(modulusSizeBits);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setPublicExponent(BigInteger e) {
      this.publicExponent = Optional.of(e);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setKidStrategy(KidStrategy kidStrategy) {
      this.kidStrategy = Optional.of(kidStrategy);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAlgorithm(Algorithm algorithm) {
      this.algorithm = Optional.of(algorithm);
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

    public JwtRsaSsaPssParameters build() throws GeneralSecurityException {
      if (!modulusSizeBits.isPresent()) {
        throw new GeneralSecurityException("key size is not set");
      }
      if (!publicExponent.isPresent()) {
        throw new GeneralSecurityException("publicExponent is not set");
      }
      if (!algorithm.isPresent()) {
        throw new GeneralSecurityException("Algorithm must be set");
      }
      if (!kidStrategy.isPresent()) {
        throw new GeneralSecurityException("KidStrategy must be set");
      }
      if (modulusSizeBits.get() < 2048) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid modulus size in bits %d; must be at least 2048 bits",
                modulusSizeBits.get()));
      }
      validatePublicExponent(publicExponent.get());
      return new JwtRsaSsaPssParameters(
          modulusSizeBits.get(), publicExponent.get(), kidStrategy.get(), algorithm.get());
    }
  }

  private final int modulusSizeBits;
  private final BigInteger publicExponent;
  private final KidStrategy kidStrategy;
  private final Algorithm algorithm;

  private JwtRsaSsaPssParameters(
      int modulusSizeBits,
      BigInteger publicExponent,
      KidStrategy kidStrategy,
      Algorithm algorithm) {
    this.modulusSizeBits = modulusSizeBits;
    this.publicExponent = publicExponent;
    this.kidStrategy = kidStrategy;
    this.algorithm = algorithm;
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

  public KidStrategy getKidStrategy() {
    return kidStrategy;
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public boolean allowKidAbsent() {
    return kidStrategy.equals(KidStrategy.CUSTOM) || kidStrategy.equals(KidStrategy.IGNORED);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof JwtRsaSsaPssParameters)) {
      return false;
    }
    JwtRsaSsaPssParameters that = (JwtRsaSsaPssParameters) o;
    return that.getModulusSizeBits() == getModulusSizeBits()
        && Objects.equals(that.getPublicExponent(), getPublicExponent())
        && that.kidStrategy.equals(kidStrategy)
        && that.algorithm.equals(algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        JwtRsaSsaPssParameters.class, modulusSizeBits, publicExponent, kidStrategy, algorithm);
  }

  @Override
  public boolean hasIdRequirement() {
    return kidStrategy.equals(KidStrategy.BASE64_ENCODED_KEY_ID);
  }

  @Override
  public String toString() {
    return "JWT RSA SSA PSS Parameters (kidStrategy: "
        + kidStrategy
        + ", algorithm "
        + algorithm
        + ", publicExponent: "
        + publicExponent
        + ", and "
        + modulusSizeBits
        + "-bit modulus)";
  }
}
