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

import com.google.crypto.tink.annotations.Alpha;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Describes the parameters of an {@link HmacKey}.
 *
 * <p>This API is annotated with Alpha because it is not yet stable and might be changed in the
 * future.
 */
@Alpha
public final class HmacParameters extends MacParameters {
  /**
   * Describes details of the mac computation.
   *
   * <p>The standard HMAC key is used for variant "NO_PREFIX". Other variants slightly change how
   * the mac is computed, or add a prefix to every computation depending on the key id.
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
    public static final Variant CRUNCHY = new Variant("CRUNCHY");
    public static final Variant LEGACY = new Variant("LEGACY");
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

  /** Builds a new HmacParameters instance. */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;
    @Nullable private Integer tagSizeBytes = null;
    private HashType hashType = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) throws GeneralSecurityException {
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTagSizeBytes(int tagSizeBytes) throws GeneralSecurityException {
      this.tagSizeBytes = tagSizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setHashType(HashType hashType) {
      this.hashType = hashType;
      return this;
    }

    private static void validateTagSizeBytes(int tagSizeBytes, HashType hashType)
        throws GeneralSecurityException {
      if (tagSizeBytes < 10) {
        throw new GeneralSecurityException(
            String.format("Invalid tag size in bytes %d; must be at least 10 bytes", tagSizeBytes));
      }
      if (hashType == HashType.SHA1) {
        if (tagSizeBytes > 20) {
          throw new GeneralSecurityException(
              String.format(
                  "Invalid tag size in bytes %d; can be at most 20 bytes for SHA1", tagSizeBytes));
        }
        return;
      }
      if (hashType == HashType.SHA224) {
        if (tagSizeBytes > 28) {
          throw new GeneralSecurityException(
              String.format(
                  "Invalid tag size in bytes %d; can be at most 28 bytes for SHA224",
                  tagSizeBytes));
        }
        return;
      }
      if (hashType == HashType.SHA256) {
        if (tagSizeBytes > 32) {
          throw new GeneralSecurityException(
              String.format(
                  "Invalid tag size in bytes %d; can be at most 32 bytes for SHA256",
                  tagSizeBytes));
        }
        return;
      }
      if (hashType == HashType.SHA384) {
        if (tagSizeBytes > 48) {
          throw new GeneralSecurityException(
              String.format(
                  "Invalid tag size in bytes %d; can be at most 48 bytes for SHA384",
                  tagSizeBytes));
        }
        return;
      }
      if (hashType == HashType.SHA512) {
        if (tagSizeBytes > 64) {
          throw new GeneralSecurityException(
              String.format(
                  "Invalid tag size in bytes %d; can be at most 64 bytes for SHA512",
                  tagSizeBytes));
        }
        return;
      }
      throw new GeneralSecurityException("unknown hash type; must be SHA256, SHA384 or SHA512");
    }

    public HmacParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("key size is not set");
      }
      if (tagSizeBytes == null) {
        throw new GeneralSecurityException("tag size is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("hash type is not set");
      }
      if (keySizeBytes < 16) {
        throw new InvalidAlgorithmParameterException(
            String.format("Invalid key size in bytes %d; must be at least 16 bytes", keySizeBytes));
      }
      validateTagSizeBytes(tagSizeBytes, hashType);
      return new HmacParameters(keySizeBytes, tagSizeBytes, variant, hashType);
    }
  }

  private final int keySizeBytes;
  private final int tagSizeBytes;
  private final Variant variant;
  private final HashType hashType;

  private HmacParameters(int keySizeBytes, int tagSizeBytes, Variant variant, HashType hashType) {
    this.keySizeBytes = keySizeBytes;
    this.tagSizeBytes = tagSizeBytes;
    this.variant = variant;
    this.hashType = hashType;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  /**
   * Returns the size of the tag which is computed cryptographically from the message.
   *
   * <p>This may differ from the total size of the tag, as for some keys, Tink prefixes the tag with
   * a key dependent output prefix.
   */
  public int getCryptographicTagSizeBytes() {
    return tagSizeBytes;
  }

  /**
   * Returns the size of the security relevant tag plus the size of the prefix with which this key
   * prefixes every tag.
   */
  public int getTotalTagSizeBytes() {
    if (variant == Variant.NO_PREFIX) {
      return getCryptographicTagSizeBytes();
    }
    if (variant == Variant.TINK) {
      return getCryptographicTagSizeBytes() + 5;
    }
    if (variant == Variant.CRUNCHY) {
      return getCryptographicTagSizeBytes() + 5;
    }
    if (variant == Variant.LEGACY) {
      return getCryptographicTagSizeBytes() + 5;
    }
    throw new IllegalStateException("Unknown variant");
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  /** Returns a hash type object. */
  public HashType getHashType() {
    return hashType;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof HmacParameters)) {
      return false;
    }
    HmacParameters that = (HmacParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes()
        && that.getTotalTagSizeBytes() == getTotalTagSizeBytes()
        && that.getVariant() == getVariant()
        && that.getHashType() == getHashType();
  }

  @Override
  public int hashCode() {
    return Objects.hash(tagSizeBytes, variant, hashType);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "HMAC Parameters (variant: "
        + variant
        + ", hashType: "
        + hashType
        + ", "
        + tagSizeBytes
        + "-byte tags, and "
        + keySizeBytes
        + "-byte key)";
  }
}
