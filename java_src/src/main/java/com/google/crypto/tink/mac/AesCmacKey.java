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

package com.google.crypto.tink.mac;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents a key computing AES-CMAC.
 *
 * <p>AES-CMAC is specified in RFC 4493. Tink supports AES-CMAC with keys of length 32 bytes (256
 * bits) only.
 */
@Immutable
public final class AesCmacKey extends MacKey {
  private final AesCmacParameters parameters;
  private final SecretBytes aesKeyBytes;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  /**
   * Builder for AesCmacKey.
   */
  public static class Builder {
    @Nullable private AesCmacParameters parameters = null;
    @Nullable private SecretBytes aesKeyBytes = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(AesCmacParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAesKeyBytes(SecretBytes aesKeyBytes) throws GeneralSecurityException {
      this.aesKeyBytes = aesKeyBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      if (parameters.getVariant() == AesCmacParameters.Variant.NO_PREFIX) {
        return Bytes.copyFrom(new byte[] {});
      }
      if (parameters.getVariant() == AesCmacParameters.Variant.LEGACY
          || parameters.getVariant() == AesCmacParameters.Variant.CRUNCHY) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
      }
      if (parameters.getVariant() == AesCmacParameters.Variant.TINK) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
      }
      throw new IllegalStateException(
          "Unknown AesCmacParametersParameters.Variant: " + parameters.getVariant());
    }

    public AesCmacKey build() throws GeneralSecurityException {
      if (parameters == null || aesKeyBytes == null) {
        throw new GeneralSecurityException("Cannot build without parameters and/or key material");
      }

      if (parameters.getKeySizeBytes() != aesKeyBytes.size()) {
        throw new GeneralSecurityException("Key size mismatch");
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
      return new AesCmacKey(parameters, aesKeyBytes, outputPrefix, idRequirement);
    }
  }

  private AesCmacKey(
      AesCmacParameters parameters,
      SecretBytes aesKeyBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.aesKeyBytes = aesKeyBytes;
    this.outputPrefix = outputPrefix;
    this.idRequirement = idRequirement;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  /** Returns the underlying AES key. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getAesKey() {
    return aesKeyBytes;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public AesCmacParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof AesCmacKey)) {
      return false;
    }
    AesCmacKey that = (AesCmacKey) o;
    return that.parameters.equals(parameters)
        && that.aesKeyBytes.equalsSecretBytes(aesKeyBytes)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
