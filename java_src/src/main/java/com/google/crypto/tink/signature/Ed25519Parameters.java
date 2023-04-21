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

package com.google.crypto.tink.signature;

import com.google.errorprone.annotations.Immutable;
import java.util.Objects;

/** This class describes the parameters of an {@link Ed25519Key}. */
public final class Ed25519Parameters extends SignatureParameters {
  /**
   * An enum-like class with constant instances, which explains how the prefix is computed.
   *
   * <p>The standard Ed25519 key is used for variant "NO_PREFIX". Other variants slightly change how
   * the signature is computed, or add a prefix to every computation depending on the key id.
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

  /** Creates an instance with NO_PREFIX variant. */
  public static Ed25519Parameters create() {
    return new Ed25519Parameters(Variant.NO_PREFIX);
  }

  /** Creates an instance with given variant. */
  public static Ed25519Parameters create(Variant variant) {
    return new Ed25519Parameters(variant);
  }

  private final Variant variant;

  private Ed25519Parameters(Variant variant) {
    this.variant = variant;
  }

  /** Returns a variant object. */
  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Ed25519Parameters)) {
      return false;
    }
    Ed25519Parameters that = (Ed25519Parameters) o;
    return that.getVariant() == getVariant();
  }

  @Override
  public int hashCode() {
    return Objects.hash(Ed25519Parameters.class, variant);
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public String toString() {
    return "Ed25519 Parameters (variant: " + variant + ")";
  }
}
