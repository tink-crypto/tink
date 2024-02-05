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

package com.google.crypto.tink.prf;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.errorprone.annotations.RestrictedApi;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/** Represents a key computing HMAC PRF. */
@Immutable
public final class HmacPrfKey extends PrfKey {
  private final HmacPrfParameters parameters;
  private final SecretBytes keyBytes;

  /** Builder for HmacPrfKey. */
  public static final class Builder {
    @Nullable private HmacPrfParameters parameters = null;
    @Nullable private SecretBytes keyBytes = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(HmacPrfParameters parameters) {
      this.parameters = parameters;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setKeyBytes(SecretBytes keyBytes) {
      this.keyBytes = keyBytes;
      return this;
    }

    public HmacPrfKey build() throws GeneralSecurityException {
      if (parameters == null || keyBytes == null) {
        throw new GeneralSecurityException("Cannot build without parameters and/or key material");
      }

      if (parameters.getKeySizeBytes() != keyBytes.size()) {
        throw new GeneralSecurityException("Key size mismatch");
      }

      return new HmacPrfKey(parameters, keyBytes);
    }
  }

  private HmacPrfKey(HmacPrfParameters parameters, SecretBytes keyBytes) {
    this.parameters = parameters;
    this.keyBytes = keyBytes;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getKeyBytes() {
    return keyBytes;
  }

  @Override
  public HmacPrfParameters getParameters() {
    return parameters;
  }

  @Override
  @Nullable
  public Integer getIdRequirementOrNull() {
    return null;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof HmacPrfKey)) {
      return false;
    }
    HmacPrfKey that = (HmacPrfKey) o;
    return that.parameters.equals(parameters) && that.keyBytes.equalsSecretBytes(keyBytes);
  }
}
