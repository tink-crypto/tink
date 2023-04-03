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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.aead.ChaCha20Poly1305Key;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class Ed25519PublicKeyTest {

  @DataPoints("requireIdVariants")
  public static final Ed25519Parameters.Variant[] REQUIRE_ID_VARIANTS =
      new Ed25519Parameters.Variant[] {
        Ed25519Parameters.Variant.TINK,
        Ed25519Parameters.Variant.CRUNCHY,
        Ed25519Parameters.Variant.LEGACY
      };

  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey key = Ed25519PublicKey.create(keyBytes);

    assertThat(key.getParameters()).isEqualTo(Ed25519Parameters.create());
    assertThat(key.getPublicKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildNoPrefixVariantExplicitAndGetProperties() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey key =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.NO_PREFIX, keyBytes, /* idRequirement= */ null);

    assertThat(key.getParameters()).isEqualTo(Ed25519Parameters.create());
    assertThat(key.getPublicKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey key =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.TINK, keyBytes, /* idRequirement= */ 0x0708090a);

    assertThat(key.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.TINK));
    assertThat(key.getPublicKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey key =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.CRUNCHY, keyBytes, /* idRequirement= */ 0x0708090a);

    assertThat(key.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.CRUNCHY));
    assertThat(key.getPublicKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void buildLegacyVariantAndGetProperties() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey key =
        Ed25519PublicKey.create(
            Ed25519Parameters.Variant.LEGACY, keyBytes, /* idRequirement= */ 0x0708090a);

    assertThat(key.getParameters())
        .isEqualTo(Ed25519Parameters.create(Ed25519Parameters.Variant.LEGACY));
    assertThat(key.getPublicKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Theory
  public void requireIdButIdIsNotSet_fails(
      @FromDataPoints("requireIdVariants") Ed25519Parameters.Variant variant) throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    assertThrows(
        GeneralSecurityException.class,
        () -> Ed25519PublicKey.create(variant, keyBytes, /* idRequirement= */ null));
  }

  @Test
  public void doesNotRequireIdButIdIsSet_fails() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));

    assertThrows(
        GeneralSecurityException.class,
        () ->
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.NO_PREFIX, keyBytes, /* idRequirement= */ 1115));
  }

  @Test
  public void invalidKeySize() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(64));

    assertThrows(GeneralSecurityException.class, () -> Ed25519PublicKey.create(keyBytes));
  }

  @Test
  public void testEqualities() throws Exception {
    Bytes keyBytes = Bytes.copyFrom(Random.randBytes(32));
    Bytes keyBytesCopy = Bytes.copyFrom(keyBytes.toByteArray());
    Bytes keyBytesDiff = Bytes.copyFrom(Random.randBytes(32));

    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes",
            Ed25519PublicKey.create(keyBytes),
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.NO_PREFIX, keyBytes, /* idRequirement= */ null),
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.NO_PREFIX, keyBytesCopy, /* idRequirement= */ null))
        .addEqualityGroup(
            "No prefix, different key bytes",
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.NO_PREFIX, keyBytesDiff, /* idRequirement= */ null))
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes",
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.TINK, keyBytes, /* idRequirement= */ 1907),
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.TINK, keyBytesCopy, /* idRequirement= */ 1907))
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes",
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.TINK, keyBytes, /* idRequirement= */ 1908))
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes",
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.CRUNCHY, keyBytes, /* idRequirement= */ 1907))
        .addEqualityGroup(
            "Legacy with key id 1908, keyBytes",
            Ed25519PublicKey.create(
                Ed25519Parameters.Variant.LEGACY, keyBytes, /* idRequirement= */ 1907))
        .doTests();
  }

  @Test
  public void testDifferentKeyTypesEquality_fails() throws Exception {
    SecretBytes secretKeyBytes = SecretBytes.randomBytes(32);
    Bytes publicKeyBytes = Bytes.copyFrom(Random.randBytes(32));

    Ed25519PublicKey ed25519Key = Ed25519PublicKey.create(publicKeyBytes);
    ChaCha20Poly1305Key chaCha20Poly1305Key = ChaCha20Poly1305Key.create(secretKeyBytes);

    assertThat(ed25519Key.equalsKey(chaCha20Poly1305Key)).isFalse();
  }
}
