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

package com.google.crypto.tink.aead;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Represents an AES-CTR-HMAC key used for computing AEAD. */
public final class AesCtrHmacAeadKey extends AeadKey {
  private final AesCtrHmacAeadParameters parameters;
  private final SecretBytes aesKeyBytes;
  private final SecretBytes hmacKeyBytes;
  private final Bytes outputPrefix;
  @Nullable private final Integer idRequirement;

  /** Builder for AesCtrHmacAeadKey. */
  public static class Builder {
    @Nullable private AesCtrHmacAeadParameters parameters = null;
    @Nullable private SecretBytes aesKeyBytes = null;
    @Nullable private SecretBytes hmacKeyBytes = null;
    @Nullable private Integer idRequirement = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(AesCtrHmacAeadParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAesKeyBytes(SecretBytes aesKeyBytes) {
      this.aesKeyBytes = aesKeyBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setHmacKeyBytes(SecretBytes hmacKeyBytes) {
      this.hmacKeyBytes = hmacKeyBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(@Nullable Integer idRequirement) {
      this.idRequirement = idRequirement;
      return this;
    }

    private Bytes getOutputPrefix() {
      if (parameters.getVariant() == AesCtrHmacAeadParameters.Variant.NO_PREFIX) {
        return Bytes.copyFrom(new byte[] {});
      }
      if (parameters.getVariant() == AesCtrHmacAeadParameters.Variant.CRUNCHY) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 0).putInt(idRequirement).array());
      }
      if (parameters.getVariant() == AesCtrHmacAeadParameters.Variant.TINK) {
        return Bytes.copyFrom(ByteBuffer.allocate(5).put((byte) 1).putInt(idRequirement).array());
      }
      throw new IllegalStateException(
          "Unknown AesCtrHmacAeadParameters.Variant: " + parameters.getVariant());
    }

    public AesCtrHmacAeadKey build() throws GeneralSecurityException {
      if (parameters == null) {
        throw new GeneralSecurityException("Cannot build without parameters");
      }

      if (aesKeyBytes == null || hmacKeyBytes == null) {
        throw new GeneralSecurityException("Cannot build without key material");
      }

      if (parameters.getAesKeySizeBytes() != aesKeyBytes.size()) {
        throw new GeneralSecurityException("AES key size mismatch");
      }

      if (parameters.getHmacKeySizeBytes() != hmacKeyBytes.size()) {
        throw new GeneralSecurityException("HMAC key size mismatch");
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
      return new AesCtrHmacAeadKey(
          parameters, aesKeyBytes, hmacKeyBytes, outputPrefix, idRequirement);
    }
  }

  private AesCtrHmacAeadKey(
      AesCtrHmacAeadParameters parameters,
      SecretBytes aesKeyBytes,
      SecretBytes hmacKeyBytes,
      Bytes outputPrefix,
      @Nullable Integer idRequirement) {
    this.parameters = parameters;
    this.aesKeyBytes = aesKeyBytes;
    this.hmacKeyBytes = hmacKeyBytes;
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

  /** Returns the underlying AES key bytes. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getAesKeyBytes() {
    return aesKeyBytes;
  }

  /** Returns the underlying HMAC key bytes. */
  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getHmacKeyBytes() {
    return hmacKeyBytes;
  }

  @Override
  public Bytes getOutputPrefix() {
    return outputPrefix;
  }

  @Override
  public AesCtrHmacAeadParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return idRequirement;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof AesCtrHmacAeadKey)) {
      return false;
    }
    AesCtrHmacAeadKey that = (AesCtrHmacAeadKey) o;
    // Since outputPrefix is a function of parameters, we can ignore it here.
    return that.parameters.equals(parameters)
        && that.aesKeyBytes.equalsSecretBytes(aesKeyBytes)
        && that.hmacKeyBytes.equalsSecretBytes(hmacKeyBytes)
        && Objects.equals(that.idRequirement, idRequirement);
  }
}
