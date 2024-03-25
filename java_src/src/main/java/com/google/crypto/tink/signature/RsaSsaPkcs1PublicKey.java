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

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.OutputPrefixUtil;
import com.google.crypto.tink.util.Bytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents a public key for the RSA SSA PKCS1 signature primitive.
 *
 * <p>Standard: https://www.rfc-editor.org/rfc/rfc8017.txt
 */
public final class RsaSsaPkcs1PublicKey extends SignaturePublicKey {
  private final RsaSsaPkcs1Parameters parameters;
  private final BigInteger modulus;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  /** Builder for RsaSsaPkcs1PublicKey. */
  public static class Builder {
    @Nullable private RsaSsaPkcs1Parameters parameters = null;
    @Nullable private BigInteger modulus = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(RsaSsaPkcs1Parameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setModulus(BigInteger modulus) {
      this.modulus = modulus;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      if (parameters.getVariant() == RsaSsaPkcs1Parameters.Variant.NO_PREFIX) {
        return OutputPrefixUtil.EMPTY_PREFIX;
      }
      if (parameters.getVariant() == RsaSsaPkcs1Parameters.Variant.LEGACY
          || parameters.getVariant() == RsaSsaPkcs1Parameters.Variant.CRUNCHY) {
        return OutputPrefixUtil.getLegacyOutputPrefix(idRequirement);
      }
      if (parameters.getVariant() == RsaSsaPkcs1Parameters.Variant.TINK) {
        return OutputPrefixUtil.getTinkOutputPrefix(idRequirement);
      }
      throw new IllegalStateException(
          "Unknown RsaSsaPkcs1Parameters.Variant: " + parameters.getVariant());
    }

    public RsaSsaPkcs1PublicKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }

      if (modulus == null) {
        throw new GeneralSecurityException("Cannot build without modulus");
      }
      int modulusSize = modulus.bitLength();
      int paramModulusSize = parameters.getModulusSizeBits();
      // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf, B.3 requires p and q
      // to be chosen such that 2^(paramModulusSize-1) < modulus < 2^paramModulusSize.
      if (modulusSize != paramModulusSize) {
        throw new GeneralSecurityException(
            "Got modulus size "
                + modulusSize
                + ", but parameters requires modulus size "
                + paramModulusSize);
      }

      if (parameters.hasIdRequirement() && idRequirement == null) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }

      if (!parameters.hasIdRequirement() && idRequirement != null) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }
      Bytes outputPrefix = getOutputPrefix();
      return new RsaSsaPkcs1PublicKey(parameters, modulus, outputPrefix, idRequirement);
    }
  }

  private RsaSsaPkcs1PublicKey(
      RsaSsaPkcs1Parameters parameters,
      BigInteger modulus,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.modulus = modulus;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
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

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public RsaSsaPkcs1Parameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof RsaSsaPkcs1PublicKey)) {
      return false;
    }
    RsaSsaPkcs1PublicKey that = (RsaSsaPkcs1PublicKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return that.parameters.equals(parameters)
        && that.modulus.equals(modulus)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
