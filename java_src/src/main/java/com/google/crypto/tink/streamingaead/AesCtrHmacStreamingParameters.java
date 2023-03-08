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

package com.google.crypto.tink.streamingaead;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the parameters of a {@link AesCtrHmacStreamingKey}.
 *
 * <p>We refer to https://developers.google.com/tink/streaming-aead/aes_ctr_hmac_streaming for a
 * complete description of the values.
 */
public class AesCtrHmacStreamingParameters extends StreamingAeadParameters {
  /** Represents the hash type used. */
  @Immutable
  public static final class HashType {
    public static final HashType SHA1 = new HashType("SHA1");
    public static final HashType SHA256 = new HashType("SHA256");
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

  public static Builder builder() {
    return new Builder();
  }

  /** Helps creating new {@link AesCtrHmacStreamingParameters} objects.. */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;

    @Nullable private Integer derivedKeySizeBytes = null;

    @Nullable private HashType hkdfHashType = null;

    @Nullable private HashType hmacHashType = null;
    @Nullable private Integer hmacTagSizeBytes = null;

    @Nullable private Integer ciphertextSegmentSizeBytes = null;

    /**
     * Sets the size of the initial key material (used as input to HKDF).
     *
     * <p>Must be at least 16, and at least equal to the value set in {@link
     * #setDerivedKeySizeBytes}
     */
    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) {
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    /**
     * Sets the size of the AES GCM key which will internally be derived.
     *
     * <p>Must be 16 or 32.
     */
    @CanIgnoreReturnValue
    public Builder setDerivedKeySizeBytes(int derivedKeySizeBytes) {
      this.derivedKeySizeBytes = derivedKeySizeBytes;
      return this;
    }

    /** Sets the type of the hash function used in HKDF. */
    @CanIgnoreReturnValue
    public Builder setHkdfHashType(HashType hkdfHashType) {
      this.hkdfHashType = hkdfHashType;
      return this;
    }

    /** Sets the type of the hash function used in the HMAC. */
    @CanIgnoreReturnValue
    public Builder setHmacHashType(HashType hmacHashType) {
      this.hmacHashType = hmacHashType;
      return this;
    }

    /** Sets the size of the Hmac tag used. */
    @CanIgnoreReturnValue
    public Builder setHmacTagSizeBytes(Integer hmacTagSizeBytes) {
      this.hmacTagSizeBytes = hmacTagSizeBytes;
      return this;
    }
    /**
     * Sets the size of a segment.
     *
     * <p>Must be at least equal 24 plus the value set in {@link #setDerivedKeySizeBytes}, and less
     * than 2^31.
     */
    @CanIgnoreReturnValue
    public Builder setCiphertextSegmentSizeBytes(int ciphertextSegmentSizeBytes) {
      this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
      return this;
    }

    /** Checks restrictions as on the devsite */
    public AesCtrHmacStreamingParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("keySizeBytes needs to be set");
      }
      if (derivedKeySizeBytes == null) {
        throw new GeneralSecurityException("derivedKeySizeBytes needs to be set");
      }
      if (hkdfHashType == null) {
        throw new GeneralSecurityException("hkdfHashType needs to be set");
      }
      if (hmacHashType == null) {
        throw new GeneralSecurityException("hmacHashType needs to be set");
      }
      if (hmacTagSizeBytes == null) {
        throw new GeneralSecurityException("hmacTagSizeBytes needs to be set");
      }
      if (ciphertextSegmentSizeBytes == null) {
        throw new GeneralSecurityException("ciphertextSegmentSizeBytes needs to be set");
      }

      if (derivedKeySizeBytes != 16 && derivedKeySizeBytes != 32) {
        throw new GeneralSecurityException(
            "derivedKeySizeBytes needs to be 16 or 32, not " + derivedKeySizeBytes);
      }
      if (keySizeBytes < derivedKeySizeBytes) {
        throw new GeneralSecurityException(
            "keySizeBytes needs to be at least derivedKeySizeBytes, i.e., " + derivedKeySizeBytes);
      }
      if (ciphertextSegmentSizeBytes <= derivedKeySizeBytes + hmacTagSizeBytes + 8) {
        throw new GeneralSecurityException(
            "ciphertextSegmentSizeBytes needs to be at least derivedKeySizeBytes + hmacTagSizeBytes"
                + " + 9, i.e., "
                + (derivedKeySizeBytes + hmacTagSizeBytes + 9));
      }

      int hmacTagSizeLowerBound = 10;
      int hmacTagSizeUpperBound = 0;
      if (hmacHashType == HashType.SHA1) {
        hmacTagSizeUpperBound = 20;
      }
      if (hmacHashType == HashType.SHA256) {
        hmacTagSizeUpperBound = 32;
      }
      if (hmacHashType == HashType.SHA512) {
        hmacTagSizeUpperBound = 64;
      }
      if (hmacTagSizeBytes < hmacTagSizeLowerBound || hmacTagSizeBytes > hmacTagSizeUpperBound) {
        throw new GeneralSecurityException(
            "hmacTagSize must be in range ["
                + hmacTagSizeLowerBound
                + ", "
                + hmacTagSizeUpperBound
                + "], but is "
                + hmacTagSizeBytes);
      }
      return new AesCtrHmacStreamingParameters(
          keySizeBytes,
          derivedKeySizeBytes,
          hkdfHashType,
          hmacHashType,
          hmacTagSizeBytes,
          ciphertextSegmentSizeBytes);
    }
  }

  private final Integer keySizeBytes;
  private final Integer derivedKeySizeBytes;
  private final HashType hkdfHashType;
  private final HashType hmacHashType;
  private final Integer hmacTagSizeBytes;
  private final Integer ciphertextSegmentSizeBytes;

  private AesCtrHmacStreamingParameters(
      Integer keySizeBytes,
      Integer derivedKeySizeBytes,
      HashType hkdfHashType,
      HashType hmacHashType,
      Integer hmacTagSizeBytes,
      Integer ciphertextSegmentSizeBytes) {
    this.keySizeBytes = keySizeBytes;
    this.derivedKeySizeBytes = derivedKeySizeBytes;
    this.hkdfHashType = hkdfHashType;
    this.hmacHashType = hmacHashType;
    this.hmacTagSizeBytes = hmacTagSizeBytes;
    this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
  }

  /** Returns the size of the initial key material. */
  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  /*  * Returns the size of the AES GCM key which will internally be derived. */
  public int getDerivedKeySizeBytes() {
    return derivedKeySizeBytes;
  }

  /** Returns the type of the hash function used in HKDF. */
  public HashType getHkdfHashType() {
    return hkdfHashType;
  }

  /** Returns the type of the hash function used in HMAC. */
  public HashType getHmacHashType() {
    return hmacHashType;
  }

  /** Returns the number of bytes used in the HMAC tag. */
  public int getHmacTagSizeBytes() {
    return hmacTagSizeBytes;
  }

  /** Returns the size a ciphertext segment has. */
  public int getCiphertextSegmentSizeBytes() {
    return ciphertextSegmentSizeBytes;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesCtrHmacStreamingParameters)) {
      return false;
    }
    AesCtrHmacStreamingParameters that = (AesCtrHmacStreamingParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes()
        && that.getDerivedKeySizeBytes() == getDerivedKeySizeBytes()
        && that.getHkdfHashType() == getHkdfHashType()
        && that.getHmacHashType() == getHmacHashType()
        && that.getHmacTagSizeBytes() == getHmacTagSizeBytes()
        && that.getCiphertextSegmentSizeBytes() == getCiphertextSegmentSizeBytes();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        keySizeBytes,
        derivedKeySizeBytes,
        hkdfHashType,
        hmacHashType,
        hmacTagSizeBytes,
        ciphertextSegmentSizeBytes);
  }

  @Override
  public String toString() {
    return "AesCtrHmacStreaming Parameters (IKM size: "
        + keySizeBytes
        + ", "
        + derivedKeySizeBytes
        + "-byte AES key, "
        + hkdfHashType
        + " for HKDF, "
        + hkdfHashType
        + " for HMAC, "
        + hmacTagSizeBytes
        + "-byte tags, "
        + ciphertextSegmentSizeBytes
        + "-byte ciphertexts)";
  }
}
