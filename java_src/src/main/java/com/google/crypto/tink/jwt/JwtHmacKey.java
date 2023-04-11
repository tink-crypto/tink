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
import com.google.crypto.tink.util.SecretBytes;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.RestrictedApi;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Optional;
import javax.annotation.Nullable;

/** Represents a JWT HMAC key to create and verify JWT using HMAC. */
class JwtHmacKey extends JwtMacKey {
  private final JwtHmacParameters parameters;
  private final SecretBytes key;
  private final Optional<Integer> idRequirement;
  private final Optional<String> kid;

  /** Helps creating new {@code JwtHmacKey} objects. */
  public static class Builder {
    private Optional<JwtHmacParameters> parameters = Optional.empty();
    private Optional<SecretBytes> keyBytes = Optional.empty();
    private Optional<Integer> idRequirement = Optional.empty();
    private Optional<String> customKid = Optional.empty();

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setParameters(JwtHmacParameters parameters) {
      this.parameters = Optional.of(parameters);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setKeyBytes(SecretBytes keyBytes) {
      this.keyBytes = Optional.of(keyBytes);
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setIdRequirement(int idRequirement) {
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
          .equals(JwtHmacParameters.KidStrategy.BASE64_ENCODED_KEY_ID)) {
        byte[] bigEndianKeyId = ByteBuffer.allocate(4).putInt(idRequirement.get()).array();
        if (customKid.isPresent()) {
          throw new GeneralSecurityException(
              "customKid must not be set for KidStrategy BASE64_ENCODED_KEY_ID");
        }
        return Optional.of(Base64.urlSafeEncode(bigEndianKeyId));
      }
      if (parameters.get().getKidStrategy().equals(JwtHmacParameters.KidStrategy.CUSTOM)) {
        if (!customKid.isPresent()) {
          throw new GeneralSecurityException("customKid needs to be set for KidStrategy CUSTOM");
        }
        return customKid;
      }
      if (parameters.get().getKidStrategy().equals(JwtHmacParameters.KidStrategy.IGNORED)) {
        if (customKid.isPresent()) {
          throw new GeneralSecurityException("customKid must not be set for KidStrategy IGNORED");
        }
        return Optional.empty();
      }
      throw new IllegalStateException("Unknown kid strategy");
    }

    public JwtHmacKey build() throws GeneralSecurityException {
      if (!parameters.isPresent()) {
        throw new GeneralSecurityException("Parameters are required");
      }
      if (!keyBytes.isPresent()) {
        throw new GeneralSecurityException("KeyBytes are required");
      }

      if (parameters.get().getKeySizeBytes() != keyBytes.get().size()) {
        throw new GeneralSecurityException("Key size mismatch");
      }

      if (parameters.get().hasIdRequirement() && !idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key without ID requirement with parameters with ID requirement");
      }

      if (!parameters.get().hasIdRequirement() && idRequirement.isPresent()) {
        throw new GeneralSecurityException(
            "Cannot create key with ID requirement with parameters without ID requirement");
      }

      return new JwtHmacKey(parameters.get(), keyBytes.get(), idRequirement, computeKid());
    }
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public static Builder builder() {
    return new Builder();
  }

  private JwtHmacKey(
      JwtHmacParameters parameters,
      SecretBytes key,
      Optional<Integer> idRequirement,
      Optional<String> kid) {
    this.parameters = parameters;
    this.key = key;
    this.idRequirement = idRequirement;
    this.kid = kid;
  }

  @RestrictedApi(
      explanation = "Accessing parts of keys can produce unexpected incompatibilities, annotate the function with @AccessesPartialKey",
      link = "https://developers.google.com/tink/design/access_control#accessing_partial_keys",
      allowedOnPath = ".*Test\\.java",
      allowlistAnnotations = {AccessesPartialKey.class})
  public SecretBytes getKeyBytes() {
    return key;
  }

  /**
   * Returns the "kid" to be used for this key.
   *
   * <p>If present, this kid will be written into the {@code kid} header during {@code
   * computeMacAndEncode}. If absent, no kid will be written.
   *
   * <p>If present, and the {@code kid} header is present, the contents of the {@code kid} header
   * needs to match the return value of this function.
   */
  @Override
  public Optional<String> getKid() {
    return kid;
  }

  @Nullable
  @Override
  public Integer getIdRequirementOrNull() {
    return idRequirement.orElse(null);
  }

  @Override
  public JwtHmacParameters getParameters() {
    return parameters;
  }

  @Override
  public boolean equalsKey(Key o) {
    if (!(o instanceof JwtHmacKey)) {
      return false;
    }
    JwtHmacKey that = (JwtHmacKey) o;
    return that.parameters.equals(parameters)
        && that.key.equalsSecretBytes(key)
        && that.kid.equals(kid)
        && that.idRequirement.equals(idRequirement);
  }
}
