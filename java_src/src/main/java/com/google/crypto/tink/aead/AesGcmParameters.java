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

package com.google.crypto.tink.aead;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Describes the parameters of an {@link AesGcmKey} */
public final class AesGcmParameters extends AeadParameters {
  /**
   * Describes how the prefix is computed. For AEAD there are three main possibilities: NO_PREFIX
   * (empty prefix), TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big endian
   * format) or CRUNCHY (prefix the ciphertext with 0x00 followed by a 4-byte key id in big endian
   * format)
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant CRUNCHY = new Variant("CRUNCHY");
    public static final Variant NO_PREFIX = new Variant("NO_PREFIX");

    private final String name;

    private Variant(String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  /**
   * Builds a new AesGcmParameters instance. The class AesGcmParameters is not responsible for
   * checking if all allowed values for the parameters are implemented and satisfy any potential
   * security policies. Some implementation may not support the full set of parameters at the moment
   * and may restrict them to certain lengths (i.e. key size may be restricted to 16 or 32 bytes).
   */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;
    @Nullable private Integer ivSizeBytes = null;
    @Nullable private Integer tagSizeBytes = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    /** Accepts key sizes of 16, 24 or 32 bytes. */
    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) throws GeneralSecurityException {
      if (keySizeBytes != 16 && keySizeBytes != 24 && keySizeBytes != 32) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size %d; only 16-byte, 24-byte and 32-byte AES keys are supported",
                keySizeBytes));
      }
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    /** IV size must greater than 0. */
    @CanIgnoreReturnValue
    public Builder setIvSizeBytes(int ivSizeBytes) throws GeneralSecurityException {
      if (ivSizeBytes <= 0) {
        throw new GeneralSecurityException(
            String.format("Invalid IV size in bytes %d; IV size must be positive", ivSizeBytes));
      }
      this.ivSizeBytes = ivSizeBytes;
      return this;
    }
    /** Tag size must be one of the following five values: 128, 120, 112, 104 or 96 bytes */
    @CanIgnoreReturnValue
    public Builder setTagSizeBytes(int tagSizeBytes) throws GeneralSecurityException {
      if (tagSizeBytes != 12
          && tagSizeBytes != 13
          && tagSizeBytes != 14
          && tagSizeBytes != 15
          && tagSizeBytes != 16) {
        throw new GeneralSecurityException(
            String.format(
                "Invalid tag size in bytes %d; value must be one of the following: 12, 13, 14, 15"
                    + " or 16 bytes",
                tagSizeBytes));
      }
      this.tagSizeBytes = tagSizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    public AesGcmParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("Key size is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("Variant is not set");
      }
      if (ivSizeBytes == null) {
        throw new GeneralSecurityException("IV size is not set");
      }

      if (tagSizeBytes == null) {
        throw new GeneralSecurityException("Tag size is not set");
      }

      return new AesGcmParameters(keySizeBytes, ivSizeBytes, tagSizeBytes, variant);
    }
  }

  private final int keySizeBytes;
  private final int ivSizeBytes;
  private final int tagSizeBytes;
  private final Variant variant;

  private AesGcmParameters(int keySizeBytes, int ivSizeBytes, int tagSizeBytes, Variant variant) {
    this.keySizeBytes = keySizeBytes;
    this.ivSizeBytes = ivSizeBytes;
    this.tagSizeBytes = tagSizeBytes;
    this.variant = variant;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  public int getIvSizeBytes() {
    return ivSizeBytes;
  }

  public int getTagSizeBytes() {
    return tagSizeBytes;
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesGcmParameters)) {
      return false;
    }
    AesGcmParameters that = (AesGcmParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes()
        && that.getIvSizeBytes() == getIvSizeBytes()
        && that.getTagSizeBytes() == getTagSizeBytes()
        && that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(keySizeBytes, ivSizeBytes, tagSizeBytes, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "AesGcm Parameters (variant: "
        + variant
        + ", "
        + ivSizeBytes
        + "-byte IV, "
        + tagSizeBytes
        + "-byte tag, and "
        + keySizeBytes
        + "-byte key)";
  }
}
