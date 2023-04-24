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
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.Optional;

/** Describes the parameters of a {@code JwtHmacKey}. */
public class JwtHmacParameters extends JwtMacParameters {
  /** Specifies how the "kid" header is handled. */
  @Immutable
  public static final class KidStrategy {
    /**
     * The "kid" is the URL safe (RFC 4648 Section 5) base64-encoded big-endian key_id in the
     * keyset.
     *
     * <p>In {@code computeMacAndEncode} Tink always adds the KID.
     *
     * <p>In {@code verifyMacAndDecode} Tink checks that the kid is present and equal to this value.
     *
     * <p>This strategy is recommended by Tink.
     */
    public static final KidStrategy BASE64_ENCODED_KEY_ID =
        new KidStrategy("BASE64_ENCODED_KEY_ID");

    /**
     * The "kid" header is ignored.
     *
     * <p>In {@code computeMacAndEncode} Tink does not write a "kid" header.
     *
     * <p>In {@code verifyMacAndDecode} Tink ignores the "kid" header.
     */
    public static final KidStrategy IGNORED = new KidStrategy("IGNORED");

    /**
     * The "kid" is fixed. It can be obtained from {@code parameters.getCustomKid()}.
     *
     * <p>In {@code computeMacAndEncode} Tink writes the "kid" header to the value given by {@code
     * parameters.getCustomKid()}.
     *
     * <p>In {@code verifyMacAndDecode} If the kid is present, it needs to match {@code
     * parameters.getCustomKid()}. If the kid is absent, it will be accepted.
     *
     * <p>Note: Tink does not allow to randomly generate new {@link JwtHmacKey} objects from
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

  /** The algorithm to be used for the mac computation. */
  @Immutable
  public static final class Algorithm {
    public static final Algorithm HS256 = new Algorithm("HS256");
    public static final Algorithm HS384 = new Algorithm("HS384");
    public static final Algorithm HS512 = new Algorithm("HS512");

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

  /** Helps creating a {@code JwtHmacParameters} object. */
  public static final class Builder {
    Optional<Integer> keySizeBytes = Optional.empty();
    Optional<KidStrategy> kidStrategy = Optional.empty();
    Optional<Algorithm> algorithm = Optional.empty();

    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) {
      this.keySizeBytes = Optional.of(keySizeBytes);
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

    public JwtHmacParameters build() throws GeneralSecurityException {
      if (!keySizeBytes.isPresent()) {
        throw new GeneralSecurityException("Key Size must be set");
      }
      if (!algorithm.isPresent()) {
        throw new GeneralSecurityException("Algorithm must be set");
      }
      if (!kidStrategy.isPresent()) {
        throw new GeneralSecurityException("KidStrategy must be set");
      }
      if (keySizeBytes.get() < 16) {
        throw new GeneralSecurityException("Key size must be at least 16 bytes");
      }
      return new JwtHmacParameters(keySizeBytes.get(), kidStrategy.get(), algorithm.get());
    }

    private Builder() {}
  }

  public static Builder builder() {
    return new Builder();
  }

  private JwtHmacParameters(int keySizeBytes, KidStrategy kidStrategy, Algorithm algorithm) {
    this.keySizeBytes = keySizeBytes;
    this.kidStrategy = kidStrategy;
    this.algorithm = algorithm;
  }

  private final int keySizeBytes;
  private final KidStrategy kidStrategy;
  private final Algorithm algorithm;

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

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
    return kidStrategy.equals(KidStrategy.CUSTOM)
        || kidStrategy.equals(KidStrategy.IGNORED);
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof JwtHmacParameters)) {
      return false;
    }
    JwtHmacParameters that = (JwtHmacParameters) o;
    return that.keySizeBytes == keySizeBytes
        && that.kidStrategy.equals(kidStrategy)
        && that.algorithm.equals(algorithm);
  }

  @Override
  public int hashCode() {
    return Objects.hash(JwtHmacParameters.class, keySizeBytes, kidStrategy, algorithm);
  }

  @Override
  public String toString() {
    return "JWT HMAC Parameters (kidStrategy: "
        + kidStrategy
        + ", Algorithm "
        + algorithm
        + ", and "
        + keySizeBytes
        + "-byte key)";
  }
}
