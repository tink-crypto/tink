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

  private static AesCmacParameters tinkParameters;
  private static AesCmacParameters legacyParameters;
  private static AesCmacParameters crunchyParameters;
  private static AesCmacParameters noPrefixParameters;

  @BeforeClass
  public static void setUpParameters() throws Exception {
    tinkParameters = AesCmacParameters.createForKeysetWithCryptographicTagSize(10, TINK);
    legacyParameters = AesCmacParameters.createForKeysetWithCryptographicTagSize(10, LEGACY);
    crunchyParameters = AesCmacParameters.createForKeysetWithCryptographicTagSize(10, CRUNCHY);
    noPrefixParameters = AesCmacParameters.createForKeysetWithCryptographicTagSize(10, NO_PREFIX);
  }

  @Test
  public void create_works() throws Exception {
    AesCmacKey.create(noPrefixParameters, SecretBytes.randomBytes(32));
    AesCmacKey.createForKeyset(tinkParameters, SecretBytes.randomBytes(32), 1907);
  }

  @Test
  public void getAesKey() throws Exception {
    SecretBytes aesKey = SecretBytes.randomBytes(32);
    assertThat(AesCmacKey.create(noPrefixParameters, aesKey).getAesKey()).isEqualTo(aesKey);
  }

  @Test
  public void getParameters() throws Exception {
    assertThat(AesCmacKey.create(noPrefixParameters, SecretBytes.randomBytes(32)).getParameters())
        .isEqualTo(noPrefixParameters);
    assertThat(
            AesCmacKey.createForKeyset(tinkParameters, SecretBytes.randomBytes(32), 1907)
                .getParameters())
        .isEqualTo(tinkParameters);
  }

  @Test
  public void getIdRequirement() throws Exception {
    assertThat(
            AesCmacKey.create(noPrefixParameters, SecretBytes.randomBytes(32))
                .getIdRequirementOrNull())
        .isNull();
    assertThat(
            AesCmacKey.createForKeyset(tinkParameters, SecretBytes.randomBytes(32), 1907)
                .getIdRequirementOrNull())
        .isEqualTo(1907);
  }

  @Test
  public void invalidCreations() throws Exception {
    // Wrong keylength
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(noPrefixParameters, SecretBytes.randomBytes(16)));
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters, SecretBytes.randomBytes(16), 199045));
    // Must use createForKeyset if we have id requirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.create(tinkParameters, SecretBytes.randomBytes(32)));
    // Must give ID with IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(tinkParameters, SecretBytes.randomBytes(32), null));
    // Must not give ID without IDRequirement
    assertThrows(
        GeneralSecurityException.class,
        () -> AesCmacKey.createForKeyset(noPrefixParameters, SecretBytes.randomBytes(32), 123));
  }

  @Test
  public void testEqualities() throws Exception {
    SecretBytes key1 = SecretBytes.randomBytes(32);
    SecretBytes key2 = SecretBytes.randomBytes(32);
    new KeyTester()
        .addEqualityGroup(
            "No prefix, key1",
            AesCmacKey.create(noPrefixParameters, key1),
            AesCmacKey.createForKeyset(noPrefixParameters, key1, /* idRequirement=*/ null))
        .addEqualityGroup(
            "No prefix, key2",
            AesCmacKey.create(noPrefixParameters, key2),
            AesCmacKey.createForKeyset(noPrefixParameters, key2, /* idRequirement=*/ null))
        .addEqualityGroup(
            "Tink 1907 key1",
            AesCmacKey.createForKeyset(tinkParameters, key1, 1907),
            AesCmacKey.createForKeyset(tinkParameters, key1, 1907))
        .addEqualityGroup(
            "Tink 1908 key1",
            AesCmacKey.createForKeyset(tinkParameters, key1, 1908),
            AesCmacKey.createForKeyset(tinkParameters, key1, 1908))
        .addEqualityGroup(
            "Legacy 1907 key1",
            AesCmacKey.createForKeyset(legacyParameters, key1, 1907),
            AesCmacKey.createForKeyset(legacyParameters, key1, 1907))
        .addEqualityGroup(
            "Crunchy 1907 key1",
            AesCmacKey.createForKeyset(crunchyParameters, key1, 1907),
            AesCmacKey.createForKeyset(crunchyParameters, key1, 1907))
        .doTests();
  }
}
