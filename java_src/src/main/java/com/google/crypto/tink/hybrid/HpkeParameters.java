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

package com.google.crypto.tink.hybrid;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import java.security.GeneralSecurityException;
import java.util.Objects;

/** Description of the parameters for an {@link HpkePublicKey} or {@link HpkePrivateKey}. */
public final class HpkeParameters extends HybridParameters {
  /** Description of the output prefix prepended to the ciphertext. */
  @Immutable
  public static final class Variant {
    /** {@code TINK}: Leading 0x01-byte followed by 4-byte key id (big endian format). */
    public static final Variant TINK = new Variant("TINK");
    /** {@code CRUNCHY}: Leading 0x00-byte followed by 4-byte key id (big endian format). */
    public static final Variant CRUNCHY = new Variant("CRUNCHY");
    /** {@code NO_PREFIX}: Empty prefix. */
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

  /**
   * HPKE algorithm identifiers.
   *
   * <p>See https://www.rfc-editor.org/rfc/rfc9180.html#section-7.
   */
  @Immutable
  private static class AlgorithmIdentifier {
    protected final String name;
    protected final int value;

    private AlgorithmIdentifier(String name, int value) {
      this.name = name;
      this.value = value;
    }

    public int getValue() {
      return value;
    }

    @Override
    public String toString() {
      return String.format("%s(0x%04x)", name, value);
    }
  }

  /**
   * HPKE KEM identifiers.
   *
   * <p>See https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.
   */
  @Immutable
  public static final class KemId extends AlgorithmIdentifier {
    public static final KemId DHKEM_P256_HKDF_SHA256 = new KemId("DHKEM_P256_HKDF_SHA256", 0x10);
    public static final KemId DHKEM_P384_HKDF_SHA384 = new KemId("DHKEM_P384_HKDF_SHA384", 0x11);
    public static final KemId DHKEM_P521_HKDF_SHA512 = new KemId("DHKEM_P521_HKDF_SHA512", 0x12);
    public static final KemId DHKEM_X25519_HKDF_SHA256 =
        new KemId("DHKEM_X25519_HKDF_SHA256", 0x20);

    private KemId(String name, int value) {
      super(name, value);
    }
  }

  /**
   * HPKE KDF identifiers.
   *
   * <p>See https://www.rfc-editor.org/rfc/rfc9180.html#section-7.2.
   */
  @Immutable
  public static final class KdfId extends AlgorithmIdentifier {
    public static final KdfId HKDF_SHA256 = new KdfId("HKDF_SHA256", 0x01);
    public static final KdfId HKDF_SHA384 = new KdfId("HKDF_SHA384", 0x02);
    public static final KdfId HKDF_SHA512 = new KdfId("HKDF_SHA512", 0x03);

    private KdfId(String name, int value) {
      super(name, value);
    }
  }

  /**
   * HPKE AEAD identifiers.
   *
   * <p>See https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3.
   */
  @Immutable
  public static final class AeadId extends AlgorithmIdentifier {
    public static final AeadId AES_128_GCM = new AeadId("AES_128_GCM", 0x01);
    public static final AeadId AES_256_GCM = new AeadId("AES_256_GCM", 0x02);
    public static final AeadId CHACHA20_POLY1305 = new AeadId("CHACHA20_POLY1305", 0x03);

    private AeadId(String name, int value) {
      super(name, value);
    }
  }

  /** Builds a new {@link HpkeParameters} instance. */
  public static final class Builder {
    private KemId kem = null;
    private KdfId kdf = null;
    private AeadId aead = null;
    private Variant variant = Variant.NO_PREFIX;

    private Builder() {}

    @CanIgnoreReturnValue
    public Builder setKemId(KemId kem) {
      this.kem = kem;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setKdfId(KdfId kdf) {
      this.kdf = kdf;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setAeadId(AeadId aead) {
      this.aead = aead;
      return this;
    }

    @CanIgnoreReturnValue
    public Builder setVariant(Variant variant) {
      this.variant = variant;
      return this;
    }

    public HpkeParameters build() throws GeneralSecurityException {
      if (kem == null) {
        throw new GeneralSecurityException("HPKE KEM parameter is not set");
      }
      if (kdf == null) {
        throw new GeneralSecurityException("HPKE KDF parameter is not set");
      }
      if (aead == null) {
        throw new GeneralSecurityException("HPKE AEAD parameter is not set");
      }
      if (variant == null) {
        throw new GeneralSecurityException("HPKE variant is not set");
      }
      return new HpkeParameters(kem, kdf, aead, variant);
    }
  }

  private final KemId kem;
  private final KdfId kdf;
  private final AeadId aead;
  private final Variant variant;

  private HpkeParameters(KemId kem, KdfId kdf, AeadId aead, Variant variant) {
    this.kem = kem;
    this.kdf = kdf;
    this.aead = aead;
    this.variant = variant;
  }

  public static Builder builder() {
    return new Builder();
  }

  public KemId getKemId() {
    return kem;
  }

  public KdfId getKdfId() {
    return kdf;
  }

  public AeadId getAeadId() {
    return aead;
  }

  public Variant getVariant() {
    return variant;
  }

  @Override
  public boolean hasIdRequirement() {
    return variant != Variant.NO_PREFIX;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof HpkeParameters)) {
      return false;
    }
    HpkeParameters other = (HpkeParameters) o;
    return kem == other.kem && kdf == other.kdf && aead == other.aead && variant == other.variant;
  }

  @Override
  public int hashCode() {
    return Objects.hash(HpkeParameters.class, kem, kdf, aead, variant);
  }
}
