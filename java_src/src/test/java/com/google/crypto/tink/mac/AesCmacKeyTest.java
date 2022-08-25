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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.internal.KeyTester;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class AesCmacKeyTest {
  private static final AesCmacParameters.Variant NO_PREFIX = AesCmacParameters.Variant.NO_PREFIX;
  private static final AesCmacParameters.Variant TINK = AesCmacParameters.Variant.TINK;
  private static final AesCmacParameters.Variant LEGACY = AesCmacParameters.Variant.LEGACY;
  private static final AesCmacParameters.Variant CRUNCHY = AesCmacParameters.Variant.CRUNCHY;

  private static AesCmacParameters tinkParameters16;
  private static AesCmacParameters legacyParameters16;
  private static AesCmacParameters crunchyParameters16;
  private static AesCmacParameters noPrefixParameters16;
  private static AesCmacParameters tinkParameters32;
  private static AesCmacParameters legacyParameters32;
  private static AesCmacParameters crunchyParameters32;
  private static AesCmacParameters noPrefixParameters32;

  @BeforeClass
  public static void setUpParameters() throws Exception {
    tinkParameters16 = AesCmacParameters.createForKeyset(16, 10, TINK);
    legacyParameters16 = AesCmacParameters.createForKeyset(16, 10, LEGACY);
    crunchyParameters16 = AesCmacParameters.createForKeyset(16, 10, CRUNCHY);
    noPrefixParameters16 = AesCmacParameters.createForKeyset(16, 10, NO_PREFIX);

    tinkParameters32 = AesCmacParameters.createForKeyset(32, 10, TINK);
    legacyParameters32 = AesCmacParameters.createForKeyset(32, 10, LEGACY);
    crunchyParameters32 = AesCmacParameters.createForKeyset(32, 10, CRUNCHY);
    noPrefixParameters32 = AesCmacParameters.createForKeyset(32, 10, NO_PREFIX);
  }

  @Test
  public void create_works() throws Exception {
    AesCmacKey.create(noPrefixParameters16, SecretBytes.randomBytes(16));
    AesCmacKey.createForKeyset(tinkParameters32, SecretBytes.randomBytes(32), 1907);
  }

  @Test
  public void create_failsOnKeySizeMismatch() throws Exception {
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(noPrefixParameters16, SecretBytes.randomBytes(32)));
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters32, SecretBytes.randomBytes(16), 1907));
  }

  @Test
  public void getAesKey() throws Exception {
    SecretBytes aesKey = SecretBytes.randomBytes(32);
    assertThat(AesCmacKey.create(noPrefixParameters32, aesKey).getAesKey()).isEqualTo(aesKey);
  }

  @Test
  public void getParameters() throws Exception {
    assertThat(AesCmacKey.create(noPrefixParameters32, SecretBytes.randomBytes(32)).getParameters())
        .isEqualTo(noPrefixParameters32);
    assertThat(
            AesCmacKey.createForKeyset(tinkParameters16, SecretBytes.randomBytes(16), 1907)
                .getParameters())
        .isEqualTo(tinkParameters16);
  }

  @Test
  public void getIdRequirement() throws Exception {
    assertThat(
            AesCmacKey.create(noPrefixParameters16, SecretBytes.randomBytes(16))
                .getIdRequirementOrNull())
        .isNull();
    assertThat(
            AesCmacKey.createForKeyset(tinkParameters32, SecretBytes.randomBytes(32), 1907)
                .getIdRequirementOrNull())
        .isEqualTo(1907);
  }

  @Test
  public void invalidCreations() throws Exception {
    // Wrong keylength
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(noPrefixParameters32, SecretBytes.randomBytes(16)));
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters32, SecretBytes.randomBytes(16), 199045));
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(noPrefixParameters16, SecretBytes.randomBytes(32)));
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters16, SecretBytes.randomBytes(32), 199045));
    // Must use createForKeyset if we have id requirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(tinkParameters32, SecretBytes.randomBytes(32)));
    // Must give ID with IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters16, SecretBytes.randomBytes(16), null));
    // Must not give ID without IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(noPrefixParameters16, SecretBytes.randomBytes(16), 123));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes key1 = SecretBytes.randomBytes(32);
    SecretBytes key2 = SecretBytes.randomBytes(32);
    SecretBytes key3 = SecretBytes.randomBytes(16);
    SecretBytes key4 = SecretBytes.randomBytes(16);
    new KeyTester()
        .addEqualityGroup(
            "No prefix, key1",
            AesCmacKey.create(noPrefixParameters32, key1),
            AesCmacKey.createForKeyset(noPrefixParameters32, key1, /* idRequirement=*/ null))
        .addEqualityGroup(
            "No prefix, key2",
            AesCmacKey.create(noPrefixParameters32, key2),
            AesCmacKey.createForKeyset(noPrefixParameters32, key2, /* idRequirement=*/ null))
        .addEqualityGroup(
            "No prefix, key3",
            AesCmacKey.create(noPrefixParameters16, key3),
            AesCmacKey.createForKeyset(noPrefixParameters16, key3, /* idRequirement=*/ null))
        .addEqualityGroup(
            "No prefix, key4",
            AesCmacKey.create(noPrefixParameters16, key4),
            AesCmacKey.createForKeyset(noPrefixParameters16, key4, /* idRequirement=*/ null))
        .addEqualityGroup(
            "Tink 1907 key1",
            AesCmacKey.createForKeyset(tinkParameters32, key1, 1907),
            AesCmacKey.createForKeyset(tinkParameters32, key1, 1907))
        .addEqualityGroup(
            "Tink 1908 key1",
            AesCmacKey.createForKeyset(tinkParameters32, key1, 1908),
            AesCmacKey.createForKeyset(tinkParameters32, key1, 1908))
        .addEqualityGroup(
            "Tink 1907 key3",
            AesCmacKey.createForKeyset(tinkParameters16, key3, 1907),
            AesCmacKey.createForKeyset(tinkParameters16, key3, 1907))
        .addEqualityGroup(
            "Tink 1908 key3",
            AesCmacKey.createForKeyset(tinkParameters16, key3, 1908),
            AesCmacKey.createForKeyset(tinkParameters16, key3, 1908))
        .addEqualityGroup(
            "Legacy 1907 key1",
            AesCmacKey.createForKeyset(legacyParameters32, key1, 1907),
            AesCmacKey.createForKeyset(legacyParameters32, key1, 1907))
        .addEqualityGroup(
            "Crunchy 1907 key1",
            AesCmacKey.createForKeyset(crunchyParameters32, key1, 1907),
            AesCmacKey.createForKeyset(crunchyParameters32, key1, 1907))
        .addEqualityGroup(
            "Legacy 1907 key3",
            AesCmacKey.createForKeyset(legacyParameters16, key3, 1907),
            AesCmacKey.createForKeyset(legacyParameters16, key3, 1907))
        .addEqualityGroup(
            "Crunchy 1907 key3",
            AesCmacKey.createForKeyset(crunchyParameters16, key3, 1907),
            AesCmacKey.createForKeyset(crunchyParameters16, key3, 1907))
        .doTests();
  }
}
