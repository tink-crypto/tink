// Copyright 2023 Google Inc.
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

import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;

/** Describes the parameters of an {@link KmsAeadKey} */
public final class LegacyKmsAeadParameters extends AeadParameters {

  /**
   * Describes how the prefix is computed. There are two main possibilities: NO_PREFIX (empty
   * prefix) and TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big endian).
   */
  @Immutable
  public static final class Variant {
    public static final Variant TINK = new Variant("TINK");
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

  private final String keyUri;
  private final Variant variant;

  private LegacyKmsAeadParameters(String keyUri, Variant variant) {
    this.keyUri = keyUri;
    this.variant = variant;
  }

  public static LegacyKmsAeadParameters create(String keyUri) throws GeneralSecurityException {
    return new LegacyKmsAeadParameters(keyUri, Variant.NO_PREFIX);
  }

  public static LegacyKmsAeadParameters create(String keyUri, Variant variant) {
    return new LegacyKmsAeadParameters(keyUri, variant);
  }

  public String keyUri() {
    return keyUri;
  }

  public Variant variant() {
    return variant;
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof LegacyKmsAeadParameters)) {
      return false;
    }
    LegacyKmsAeadParameters that = (LegacyKmsAeadParameters) o;
    return that.keyUri.equals(keyUri) && that.variant.equals(variant);
  }

  @Override
  public int hashCode() {
    return Objects.hash(LegacyKmsAeadParameters.class, keyUri, variant);
  }

  @Override
  public String toString() {
    return "LegacyKmsAead Parameters (keyUri: " + keyUri + ", variant: " + variant + ")";
  }
}
