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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class ChaCha20Poly1305KeyTest {
  @Test
  public void buildNoPrefixVariantAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    ChaCha20Poly1305Key key = ChaCha20Poly1305Key.create(keyBytes);
    assertThat(key.getParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildNoPrefixVariantExplicitAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, null);
    assertThat(key.getParameters()).isEqualTo(ChaCha20Poly1305Parameters.create());
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix()).isEqualTo(Bytes.copyFrom(new byte[] {}));
    assertThat(key.getIdRequirementOrNull()).isNull();
  }

  @Test
  public void buildTinkVariantAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 0x0708090a);
    assertThat(key.getParameters())
        .isEqualTo(ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.TINK));
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x01, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void buildCrunchyVariantAndGetProperties() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    ChaCha20Poly1305Key key =
        ChaCha20Poly1305Key.create(
            ChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, 0x0708090a);
    assertThat(key.getParameters())
        .isEqualTo(ChaCha20Poly1305Parameters.create(ChaCha20Poly1305Parameters.Variant.CRUNCHY));
    assertThat(key.getKeyBytes()).isEqualTo(keyBytes);
    assertThat(key.getOutputPrefix())
        .isEqualTo(Bytes.copyFrom(new byte[] {0x00, 0x07, 0x08, 0x09, 0x0a}));
    assertThat(key.getIdRequirementOrNull()).isEqualTo(0x708090a);
  }

  @Test
  public void wrongIdRequirement_throws() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ChaCha20Poly1305Key.create(
                ChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, 1115));
    assertThrows(
        GeneralSecurityException.class,
        () ->
            ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, null));
    assertThrows(
        GeneralSecurityException.class,
        () -> ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.TINK, keyBytes, null));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes keyBytes = SecretBytes.randomBytes(32);
    SecretBytes keyBytesCopy =
        SecretBytes.copyFrom(
            keyBytes.toByteArray(InsecureSecretKeyAccess.get()), InsecureSecretKeyAccess.get());
    SecretBytes keyBytesDiff = SecretBytes.randomBytes(32);

    new KeyTester()
        .addEqualityGroup(
            "No prefix, keyBytes",
            ChaCha20Poly1305Key.create(
                ChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytes, null),
            ChaCha20Poly1305Key.create(keyBytes),
            ChaCha20Poly1305Key.create(
                ChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytesCopy, null))
        .addEqualityGroup(
            "No prefix, different key bytes",
            ChaCha20Poly1305Key.create(
                ChaCha20Poly1305Parameters.Variant.NO_PREFIX, keyBytesDiff, null))
        .addEqualityGroup(
            "Tink with key id 1907, keyBytes32",
            ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 1907),
            ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.TINK, keyBytesCopy, 1907))
        .addEqualityGroup(
            "Tink with key id 1908, keyBytes32",
            ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.TINK, keyBytes, 1908))
        .addEqualityGroup(
            "Crunchy with key id 1907, keyBytes32",
            ChaCha20Poly1305Key.create(ChaCha20Poly1305Parameters.Variant.CRUNCHY, keyBytes, 1907))
        .doTests();
  }
}
