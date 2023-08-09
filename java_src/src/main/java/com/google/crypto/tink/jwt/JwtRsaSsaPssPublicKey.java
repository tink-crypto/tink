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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.subtle.Base64;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * Represents a public key for the JWT RSA SSA PSS signature primitive.
 *
 * <p>Standard: https://datatracker.ietf.org/doc/html/rfc7518
 */
public final class JwtRsaSsaPssPublicKey extends JwtSignaturePublicKey {
  private final JwtRsaSsaPssParameters parameters;
  private final BigInteger modulus;
  private final Optional<Integer> idRequirement;
  private final Optional<String> kid;

  /** Builder for JwtRsaSsaPssPublicKey. */
  public static class Builder {
    private Optional<JwtRsaSsaPssParameters> parameters = Optional.empty();
    private Optional<BigInteger> modulus = Optional.empty();
    private Optional<Integer> idRequirement = Optional.empty();
    private Optional<String> customKid = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(JwtRsaSsaPssParameters parameters) {
      this.parameters = Optional.of(parameters);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setModulus(BigInteger modulus) {
      this.modulus = Optional.of(modulus);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(Integer idRequirement) {
      this.idRequirement = Optional.of(idRequirement);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setCustomKid(String customKid) {
      this.customKid = Optional.of(customKid);
      return this;
    }

    private Optional<String> computeKid() throws GeneralSecurityException {
      if (parameters
          .get()
          .getKidStrategy()
          .equals(JwtRsaSsaPssParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException(
              "customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
        }
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement.get()).array();
        return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
      }
      if (parameters.get().getKidStrategy().equals(JwtRsaSsaPssParameters.KidStrategy.CUSTOM)) {
        if (!customKid.isPresent()) {
          throw new GeneralSecurityException("customKid needs to be set for KidStrategy CUSTOM");
        }
        return customKid;
      }
      if (parameters.get().getKidStrategy().equals(JwtRsaSsaPssParameters.KidStrategy.IGNORED)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException("customKid must not be set for KidStrategy IGNORED");
        }
        return Optional.empty();
      }
      throw new IllegalStateException("Unknown kid strategy");
    }

    public JwtRsaSsaPssPublicKey build() throws GeneralSecurityException {
      if (!parameters.isPresent()) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }

      if (!modulus.isPresent()) {
        throw new GeneralSecurityException("Cannot build without modulus");
      }
      int modulusSize = modulus.get().bitLength();
      int paramModulusSize = parameters.get().getModulusSizeBits();
      // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, B.3 requires p and q
      // to be chosen such that 2^(paramModulusSize-1) < modulus < 2^paramModulusSize.
      if (modulusSize != paramModulusSize) {
        throw new GeneralSecurityException(
            "Got modulus size "
                + modulusSize
                + ", but parameters requires modulus size "
                + paramModulusSize);
      }

      if (parameters.get().hasIdRequirement() && !idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }

      if (!parameters.get().hasIdRequirement() && idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }

      return new JwtRsaSsaPssPublicKey(
          parameters.get(), modulus.get(), idRequirement, computeKid());
    }
  }

  private JwtRsaSsaPssPublicKey(
      JwtRsaSsaPssParameters parameters,
      BigInteger modulus,
      Optional<Integer> idRequirement,
      Optional<String> kid) {
    this.parameters = parameters;
    this.modulus = modulus;
    this.idRequirement = idRequirement;
    this.kid = kid;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  /** Returns the underlying key bytes. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public BigInteger getModulus() {
    return modulus;
  }

  /**
   * Returns the "kid" to be used for this key.
   *
   * <p>If present, this kid will be written into the {@code kid} header during {{@code
   * PublicKeySign#signAndEncode}. If absent, no kid will be written.
   *
   * <p>If present, and the {@code kid} header is present, the contents of the {@code kid} header
   * needs to match the return value of this function.
   */
  @Override
  public Optional<String> getKid() {
    return kid;
  }

  @Override
  public JwtRsaSsaPssParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement.orElse(null);
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtRsaSsaPssPublicKey)) {
      return false;
    }
    JwtRsaSsaPssPublicKey that = (JwtRsaSsaPssPublicKey) o;
    return that.parameters.equals(parameters)
        && that.modulus.equals(modulus)
        && that.kid.equals(kid)
        && that.idRequirement.equals(idRequirement);
  }
}
