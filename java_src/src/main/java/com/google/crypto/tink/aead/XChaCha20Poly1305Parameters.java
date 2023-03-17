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

import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** Describes the parameters of an {@link XChaChaPoly1305Key}. */
public final class XChaCha20Poly1305Parameters extends AeadParameters {
  /**
   * Describes how the prefix is computed. For AEAD there are three main possibilities: NO_PREFIX
   * (empty prefix), TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big endian
   * format) or CRUNCHY (prefix the ciphertext with 0x00 followed by a 4-byte key id in big endian
   * format).
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

  public static XChaCha20Poly1305Parameters create() {
    return new XChaCha20Poly1305Parameters(Variant.NO_PREFIX);
  }

  public static XChaCha20Poly1305Parameters create(Variant variant) {
    return new XChaCha20Poly1305Parameters(variant);
  }

  private final Variant variant;

  private XChaCha20Poly1305Parameters(Variant variant) {
    this.variant = variant;
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof XChaCha20Poly1305Parameters)) {
      return false;
    }
    XChaCha20Poly1305Parameters that = (XChaCha20Poly1305Parameters) o;
    return that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(XChaCha20Poly1305Parameters.class, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "XChaCha20Poly1305 Parameters (variant: " + variant + ")";
  }
}
