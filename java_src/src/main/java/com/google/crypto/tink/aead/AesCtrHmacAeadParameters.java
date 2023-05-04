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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;
import javax.annotation.Nullable;

/** Describes the parameters of an {@link AesCtrHmacAeadKey}. */
public final class AesCtrHmacAeadParameters extends AeadParameters {
  private static final int PREFIX_SIZE_IN_BYTES = 5;
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

  /** The Hash algorithm used for the HMAC. */
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

  /** Builds a new AesCtrHmacAeadParameters instance. */
  public static final class Builder {
    @Nullable private Integer aesKeySizeBytes = null;
    @Nullable private Integer hmacKeySizeBytes = null;
    @Nullable private Integer ivSizeBytes = null;
    @Nullable private Integer tagSizeBytes = null;
    private HashType hashType = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    /** Accepts key sizes of 16, 24 or 32 bytes. */
    @CanIgnoreReturnValue
    public Builder setAesKeySizeBytes(int aesKeySizeBytes) throws GeneralSecurityException {
      if (aesKeySizeBytes != 16 && aesKeySizeBytes != 24 && aesKeySizeBytes != 32) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size %d; only 16-byte, 24-byte and 32-byte AES keys are supported",
                aesKeySizeBytes));
      }
      this.aesKeySizeBytes = aesKeySizeBytes;
      return this;
    }

    /** Accepts key sizes of at least 16 bytes. */
    @CanIgnoreReturnValue
    public Builder setHmacKeySizeBytes(int hmacKeySizeBytes) throws GeneralSecurityException {
      if (hmacKeySizeBytes < 16) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size in bytes %d; HMAC key must be at least 16 bytes",
                hmacKeySizeBytes));
      }
      this.hmacKeySizeBytes = hmacKeySizeBytes;
      return this;
    }

    /** IV size must be between 12 and 16 bytes. */
    @CanIgnoreReturnValue
    public Builder setIvSizeBytes(int ivSizeBytes) throws GeneralSecurityException {
      if (ivSizeBytes < 12 || ivSizeBytes > 16) {
        throw new GeneralSecurityException(
            String.format(
                "Invalid IV size in bytes %d; IV size must be between 12 and 16 bytes",
                ivSizeBytes));
      }
      this.ivSizeBytes = ivSizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setTagSizeBytes(int tagSizeBytes) throws GeneralSecurityException {
      if (tagSizeBytes < 10) {
        throw new GeneralSecurityException(
            String.format("Invalid tag size in bytes %d; must be at least 10 bytes", tagSizeBytes));
      }
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
      throw new GeneralSecurityException(
          "unknown hash type; must be SHA1, SHA224, SHA256, SHA384 or SHA512");
    }

    public AesCtrHmacAeadParameters build() throws GeneralSecurityException {
      if (aesKeySizeBytes == null) {
        throw new GeneralSecurityException("AES key size is not set");
      }
      if (hmacKeySizeBytes == null) {
        throw new GeneralSecurityException("HMAC key size is not set");
      }
      if (ivSizeBytes == null) {
        throw new GeneralSecurityException("iv size is not set");
      }
      if (tagSizeBytes == null) {
        throw new GeneralSecurityException("tag size is not set");
      }
      if (hashType == null) {
        throw new GeneralSecurityException("hash type is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("variant is not set");
      }
      validateTagSizeBytes(tagSizeBytes, hashType);
      return new AesCtrHmacAeadParameters(
          aesKeySizeBytes, hmacKeySizeBytes, ivSizeBytes, tagSizeBytes, variant, hashType);
    }
  }

  private final int aesKeySizeBytes;
  private final int hmacKeySizeBytes;
  private final int ivSizeBytes;
  private final int tagSizeBytes;
  private final Variant variant;
  private final HashType hashType;

  private AesCtrHmacAeadParameters(
      int aesKeySizeBytes,
      int hmacKeySizeBytes,
      int ivSizeBytes,
      int tagSizeBytes,
      Variant variant,
      HashType hashType) {
    this.aesKeySizeBytes = aesKeySizeBytes;
    this.hmacKeySizeBytes = hmacKeySizeBytes;
    this.ivSizeBytes = ivSizeBytes;
    this.tagSizeBytes = tagSizeBytes;
    this.variant = variant;
    this.hashType = hashType;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getAesKeySizeBytes() {
    return aesKeySizeBytes;
  }

  public int getHmacKeySizeBytes() {
    return hmacKeySizeBytes;
  }

  public int getTagSizeBytes() {
    return tagSizeBytes;
  }

  public int getIvSizeBytes() {
    return ivSizeBytes;
  }

  /**
   * Returns the size of the overhead added to the actual ciphertext (i.e. the size of the IV plus
   * the size of the security relevant tag plus the size of the prefix with which this key prefixes
   * the ciphertext.
   */
  public int getCiphertextOverheadSizeBytes() {
    if (variant == Variant.NO_PREFIX) {
      return getTagSizeBytes() + getIvSizeBytes();
    }
    if (variant == Variant.TINK || variant == Variant.CRUNCHY) {
      return getTagSizeBytes() + getIvSizeBytes() + PREFIX_SIZE_IN_BYTES;
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
    if (!(o instanceof AesCtrHmacAeadParameters)) {
      return false;
    }
    AesCtrHmacAeadParameters that = (AesCtrHmacAeadParameters) o;
    return that.getAesKeySizeBytes() == getAesKeySizeBytes()
        && that.getHmacKeySizeBytes() == getHmacKeySizeBytes()
        && that.getIvSizeBytes() == getIvSizeBytes()
        && that.getTagSizeBytes() == getTagSizeBytes()
        && that.getVariant() == getVariant()
        && that.getHashType() == getHashType();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        AesCtrHmacAeadParameters.class,
        aesKeySizeBytes,
        hmacKeySizeBytes,
        ivSizeBytes,
        tagSizeBytes,
        variant,
        hashType);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "AesCtrHmacAead Parameters (variant: "
        + variant
        + ", hashType: "
        + hashType
        + ", "
        + ivSizeBytes
        + "-byte IV, and "
        + tagSizeBytes
        + "-byte tags, and "
        + aesKeySizeBytes
        + "-byte AES key, and "
        + hmacKeySizeBytes
        + "-byte HMAC key)";
  }
}
