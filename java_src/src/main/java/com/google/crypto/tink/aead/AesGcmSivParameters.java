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

/** Describes the parameters of an {@link AesGcmSivSivKey} */
public final class AesGcmSivParameters extends AeadParameters {
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

  /** Builds a new AesGcmSivParameters instance. */
  public static final class Builder {
    @Nullable private Integer keySizeBytes = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    /** Accepts key sizes of 16 and 32 bytes. */
    @CanIgnoreReturnValue
    public Builder setKeySizeBytes(int keySizeBytes) throws GeneralSecurityException {
      if (keySizeBytes != 16 && keySizeBytes != 32) {
        throw new InvalidAlgorithmParameterException(
            String.format(
                "Invalid key size %d; only 16-byte and 32-byte AES keys are supported",
                keySizeBytes));
      }
      this.keySizeBytes = keySizeBytes;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    public AesGcmSivParameters build() throws GeneralSecurityException {
      if (keySizeBytes == null) {
        throw new GeneralSecurityException("Key size is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("Variant is not set");
      }
      return new AesGcmSivParameters(keySizeBytes, variant);
    }
  }

  private final int keySizeBytes;
  private final Variant variant;

  private AesGcmSivParameters(int keySizeBytes, Variant variant) {
    this.keySizeBytes = keySizeBytes;
    this.variant = variant;
  }

  public static Builder builder() {
    return new Builder();
  }

  public int getKeySizeBytes() {
    return keySizeBytes;
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesGcmSivParameters)) {
      return false;
    }
    AesGcmSivParameters that = (AesGcmSivParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes() && that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(AesGcmSivParameters.class, keySizeBytes, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "AesGcmSiv Parameters (variant: " + variant + ", " + keySizeBytes + "-byte key)";
  }
}
