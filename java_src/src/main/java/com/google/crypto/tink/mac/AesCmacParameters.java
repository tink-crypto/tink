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

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Objects;

/** Describes the parameters of an {@link AesCmacKey}. */
public final class AesCmacParameters extends MacParameters {
  /**
   * Describes details of the mac computation.
   *
   * <p>The usual AES CMAC key is used for variant "NO_PREFIX". Other variants slightly change how
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

  private final int keySizeBytes;
  private final int tagSizeBytes;
  private final Variant variant;

  private AesCmacParameters(int keySizeBytes, int tagSizeBytes, Variant variant) {
    this.keySizeBytes = keySizeBytes;
    this.tagSizeBytes = tagSizeBytes;
    this.variant = variant;
  }

  /** Equivalent to {@code createForKeysetWithCryptographicTagSize(tagSize, Variant.NO_PREFIX);} */
  public static AesCmacParameters create(int keySizeBytes, int tagSizeBytes)
      throws GeneralSecurityException {
    return createForKeyset(keySizeBytes, tagSizeBytes, Variant.NO_PREFIX);
  }

  /**
   * Creates a new parameters object.
   *
   * @throws GeneralSecurityException if tagSizeBytes not in {10, …, 16}.
   */
  public static AesCmacParameters createForKeyset(
      int keySizeBytes, int tagSizeBytes, Variant variant) throws GeneralSecurityException {
    if (keySizeBytes != 16 && keySizeBytes != 32) {
      throw new InvalidAlgorithmParameterException(
          String.format(
              "Invalid key size %d; only 128-bit and 256-bit AES keys are supported",
              keySizeBytes * 8));
    }

    if (tagSizeBytes < 10 || 16 < tagSizeBytes) {
      throw new GeneralSecurityException("Invalid tag size for AesCmacParameters: " + tagSizeBytes);
    }

    return new AesCmacParameters(keySizeBytes, tagSizeBytes, variant);
  }

  /** Returns the size of the key. */
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

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof AesCmacParameters)) {
      return false;
    }
    AesCmacParameters that = (AesCmacParameters) o;
    return that.getKeySizeBytes() == getKeySizeBytes()
        && that.getTotalTagSizeBytes() == getTotalTagSizeBytes()
        && that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(tagSizeBytes, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "AES-CMAC Parameters (variant: "
        + variant
        + ", "
        + tagSizeBytes
        + "-byte tags, and "
        + keySizeBytes
        + "-byte key)";
  }
}
