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

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link HmacPrfKey}.
 *
 * <p>This API is annotated with {@link com.google.crypto.tink.annotations.Alpha} because it is not
 * yet stable and might change in the future.
 */
@Alpha
public final class HmacPrfParameters extends PrfParameters {
  private static final int MIN_KEY_SIZE = 16;

  /** The Hash algorithm used. */
  @Immutable
  public static final class HashType {
    public static final HashType SHA1 = new HashType("SHA1");
    public static final HashType SHA224 = new HashType("SHA224");
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

  /** Builder for HmacPrfParameters. */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;
    @Nullable private HashType hashType = null;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) throws GeneralSecurityException {
      if (keySizeBytes < MIN_KEY_SIZE) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size %d; only 128-bit or larger are supported", keySizeBytes * 8));
      }
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setHashType(HashType hashType) {
      this.hashType = hashType;
      return this;
    }

    public HmacPrfParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("key size is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("hash type is not set");
      }
      return new HmacPrfParameters(keySizeBytes, hashType);
    }
  }

  private final int keySizeBytes;
  private final HashType hashType;

  private HmacPrfParameters(int keySizeBytes, HashType hashType) {
    this.keySizeBytes = keySizeBytes;
    this.hashType = hashType;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  public HashType getHashType() {
    return hashType;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof HmacPrfParameters)) {
      return false;
    }
    HmacPrfParameters that = (HmacPrfParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes() && that.getHashType() == getHashType();
  }

  @Override
  public int hashCode() {
    return Objects.hash(keySizeBytes, hashType);
  }

  @Override
  public boolean hasIdRequirement() {
    return false;
  }

  @Override
  public String toString() {
    return "HMAC PRF Parameters (hashType: " + hashType + " and " + keySizeBytes + "-byte key)";
  }
}
