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

import com.google.crypto.tink.internal.EllipticCurvesUtil;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.spec.ECParameterSpec;
import java.util.Objects;
import java.util.Optional;

/** Describes the parameters of a {@code JwtEcdsaPrivateKey} or a {@code JwtEcdsaPublicKey}. */
public final class JwtEcdsaParameters extends JwtSignatureParameters {
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
     * <p>Note: Tink does not allow to randomly generate new {@link JwtEcdsaKey} objects from
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
    /** ECDSA using P-256 and SHA-256 */
    public static final Algorithm ES256 =
        new Algorithm("ES256", EllipticCurvesUtil.NIST_P256_PARAMS);
    /** ECDSA using P-384 and SHA-384 */
    public static final Algorithm ES384 =
        new Algorithm("ES384", EllipticCurvesUtil.NIST_P384_PARAMS);
    /** ECDSA using P-521 and SHA-512 */
    public static final Algorithm ES512 =
        new Algorithm("ES512", EllipticCurvesUtil.NIST_P521_PARAMS);

    private final String name;

    @SuppressWarnings("Immutable") // ECParameterSpec is immutable
    private final ECParameterSpec ecParameterSpec;

    private Algorithm(String name, ECParameterSpec ecParameterSpec) {
      this.name = name;
      this.ecParameterSpec = ecParameterSpec;
    }

    @Override
    public String toString() {
      return name;
    }

    public String getStandardName() {
      return name;
    }

    ECParameterSpec getECParameterSpec() {
      return ecParameterSpec;
    }
  }

  /** Helps creating a {@code JwtEcdsaParameters} object. */
  public static final class Builder {
    Optional<KidStrategy> kidStrategy = Optional.empty();
    Optional<Algorithm> algorithm = Optional.empty();

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

    public JwtEcdsaParameters build() throws GeneralSecurityException {
      if (!algorithm.isPresent()) {
        throw new GeneralSecurityException("Algorithm must be set");
      }
      if (!kidStrategy.isPresent()) {
        throw new GeneralSecurityException("KidStrategy must be set");
      }
      return new JwtEcdsaParameters(kidStrategy.get(), algorithm.get());
    }

    private Builder() {}
  }

  public static Builder builder() {
    return new Builder();
  }

  private JwtEcdsaParameters(KidStrategy kidStrategy, Algorithm algorithm) {
    this.kidStrategy = kidStrategy;
    this.algorithm = algorithm;
  }

  private final KidStrategy kidStrategy;
  private final Algorithm algorithm;

  public KidStrategy getKidStrategy() {
    return kidStrategy;
  }

  public Algorithm getAlgorithm() {
    return algorithm;
  }

  @Override
  public boolean hasIdRequirement() {
    return kidStrategy.equals(KidStrategy.BASE64_ENCODED_KEY_ID);
  }

  @Override
  public boolean allowKidAbsent() {
    return kidStrategy.equals(KidStrategy.CUSTOM) || kidStrategy.equals(KidStrategy.IGNORED);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof JwtEcdsaParameters)) {
      return false;
    }
    JwtEcdsaParameters that = (JwtEcdsaParameters) o;
    return that.kidStrategy.equals(kidStrategy) && that.algorithm.equals(algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(JwtEcdsaParameters.class, kidStrategy, algorithm);
  }

  @Override
  public String toString() {
    return "JWT ECDSA Parameters (kidStrategy: " + kidStrategy + ", Algorithm " + algorithm + ")";
  }
}
