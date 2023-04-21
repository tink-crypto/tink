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

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Represents the parameters of a {@link AesGcmHkdfStreamingKey}.
 *
 * <p>We refer to https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming for a
 * complete description of the values.
 */
public class AesGcmHkdfStreamingParameters extends StreamingAeadParameters {
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

  /** Helps creating new {@link AesGcmHkdfStreamingParameters} objects. */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;

    @Nullable private Integer derivedAesGcmKeySizeBytes = null;

    @Nullable private HashType hkdfHashType = null;

    @Nullable private Integer ciphertextSegmentSizeBytes = null;

    /**
     * Sets the size of the initial key material (used as input to HKDF).
     *
     * <p>Must be at least 16, and at least equal to the value set in {@link
     * #setDerivedAesGcmKeySizeBytes}
     */
    public Builder setKeySizeBytes(int keySizeBytes) {
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    /**
     * Sets the size of the AES GCM key which will internally be derived.
     *
     * <p>Must be 16 or 32.
     */
    public Builder setDerivedAesGcmKeySizeBytes(int derivedAesGcmKeySizeBytes) {
      this.derivedAesGcmKeySizeBytes = derivedAesGcmKeySizeBytes;
      return this;
    }

    /** Sets the type of the hash function used in HKDF. */
    public Builder setHkdfHashType(HashType hkdfHashType) {
      this.hkdfHashType = hkdfHashType;
      return this;
    }

    /**
     * Sets the size of a segment.
     *
     * <p>Must be at least equal 24 plus the value set in {@link #setDerivedAesGcmKeySizeBytes}, and
     * less than 2^31.
     */
    public Builder setCiphertextSegmentSizeBytes(int ciphertextSegmentSizeBytes) {
      this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
      return this;
    }

    /** Checks restrictions as on the devsite */
    public AesGcmHkdfStreamingParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("keySizeBytes needs to be set");
      }
      if (derivedAesGcmKeySizeBytes == null) {
        throw new GeneralSecurityException("derivedAesGcmKeySizeBytes needs to be set");
      }
      if (hkdfHashType == null) {
        throw new GeneralSecurityException("hkdfHashType needs to be set");
      }
      if (ciphertextSegmentSizeBytes == null) {
        throw new GeneralSecurityException("ciphertextSegmentSizeBytes needs to be set");
      }

      if (derivedAesGcmKeySizeBytes != 16 && derivedAesGcmKeySizeBytes != 32) {
        throw new GeneralSecurityException(
            "derivedAesGcmKeySizeBytes needs to be 16 or 32, not " + derivedAesGcmKeySizeBytes);
      }
      if (keySizeBytes < derivedAesGcmKeySizeBytes) {
        throw new GeneralSecurityException(
            "keySizeBytes needs to be at least derivedAesGcmKeySizeBytes, i.e., "
                + derivedAesGcmKeySizeBytes);
      }
      if (ciphertextSegmentSizeBytes <= derivedAesGcmKeySizeBytes + 24) {
        throw new GeneralSecurityException(
            "ciphertextSegmentSizeBytes needs to be at least derivedAesGcmKeySizeBytes + 25, i.e., "
                + (derivedAesGcmKeySizeBytes + 25));
      }
      return new AesGcmHkdfStreamingParameters(
          keySizeBytes, derivedAesGcmKeySizeBytes, hkdfHashType, ciphertextSegmentSizeBytes);
    }
  }

  private final Integer keySizeBytes;
  private final Integer derivedAesGcmKeySizeBytes;
  private final HashType hkdfHashType;
  private final Integer ciphertextSegmentSizeBytes;

  private AesGcmHkdfStreamingParameters(
      Integer keySizeBytes,
      Integer derivedAesGcmKeySizeBytes,
      HashType hkdfHashType,
      Integer ciphertextSegmentSizeBytes) {
    this.keySizeBytes = keySizeBytes;
    this.derivedAesGcmKeySizeBytes = derivedAesGcmKeySizeBytes;
    this.hkdfHashType = hkdfHashType;
    this.ciphertextSegmentSizeBytes = ciphertextSegmentSizeBytes;
  }

  /** Returns the size of the initial key material. */
  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  /** Returns the size of the AES GCM key which will internally be derived. */
  public int getDerivedAesGcmKeySizeBytes() {
    return derivedAesGcmKeySizeBytes;
  }

  /** Returns the type of the hash function used in HKDF. */
  public HashType getHkdfHashType() {
    return hkdfHashType;
  }

  /** Returns the size a ciphertext segment has. */
  public int getCiphertextSegmentSizeBytes() {
    return ciphertextSegmentSizeBytes;
  }


  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesGcmHkdfStreamingParameters)) {
      return false;
    }
    AesGcmHkdfStreamingParameters that = (AesGcmHkdfStreamingParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes()
        && that.getDerivedAesGcmKeySizeBytes() == getDerivedAesGcmKeySizeBytes()
        && that.getHkdfHashType() == getHkdfHashType()
        && that.getCiphertextSegmentSizeBytes() == getCiphertextSegmentSizeBytes();
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        AesGcmHkdfStreamingParameters.class,
        keySizeBytes,
        derivedAesGcmKeySizeBytes,
        hkdfHashType,
        ciphertextSegmentSizeBytes);
  }

  @Override
  public String toString() {
    return "AesGcmHkdfStreaming Parameters (IKM size: "
        + keySizeBytes
        + ", "
        + derivedAesGcmKeySizeBytes
        + "-byte AES GCM key, "
        + hkdfHashType
        + " for HKDF "
        + ciphertextSegmentSizeBytes
        + "-byte ciphertexts)";
  }

}
