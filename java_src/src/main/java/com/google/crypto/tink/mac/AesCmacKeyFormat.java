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
import java.util.Objects;

/** Describes a format of an {@link AesCmacKey}. */
public final class AesCmacKeyFormat extends MacKeyFormat {
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

  private final int tagSizeBytes;
  private final Variant variant;

  private AesCmacKeyFormat(int tagSizeBytes, Variant variant) {
    this.tagSizeBytes = tagSizeBytes;
    this.variant = variant;
  }

  /** Equivalent to {@code createForKeysetWithCryptographicTagSize(tagSize, Variant.NO_PREFIX);} */
  public static AesCmacKeyFormat create(int tagSize) throws GeneralSecurityException {
    return createForKeysetWithCryptographicTagSize(tagSize, Variant.NO_PREFIX);
  }

  /**
   * Creates a new key format object.
   *
   * @throws GeneralSecurityException if tagSizeBytes not in {10, …, 16}.
   */
  public static AesCmacKeyFormat createForKeysetWithCryptographicTagSize(
      int tagSizeBytes, Variant variant) throws GeneralSecurityException {
    if (tagSizeBytes < 10 || 16 < tagSizeBytes) {
      throw new GeneralSecurityException("Invalid tag size for AesCmacKeyFormat: " + tagSizeBytes);
    }
    return new AesCmacKeyFormat(tagSizeBytes, variant);
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
    if (!(o instanceof AesCmacKeyFormat)) {
      return false;
    }
    AesCmacKeyFormat that = (AesCmacKeyFormat) o;
    return that.getTotalTagSizeBytes() == getTotalTagSizeBytes()
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
    return "AES-CMAC Key Format (variant: " + variant + ", " + tagSizeBytes + "-byte tags)";
  }
}
